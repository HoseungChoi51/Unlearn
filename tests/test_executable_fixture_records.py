from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_fixture_bundle import (  # noqa: E402
    validate_executable_fixture_bundle,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_fixture_records import (  # noqa: E402
    ExecutableFixtureRecordError,
    build_checksum_manifest_fixture_bundle,
    build_manifest_copy_fixture_bundle,
)
from cbds.executable_static_registry import (  # noqa: E402
    build_public_method_development_registry,
)


REGISTRY = build_public_method_development_registry()
MANIFEST_TASKS = tuple(
    task for task in REGISTRY.tasks if task.family_id == "manifest-copy"
)
CHECKSUM_TASKS = tuple(
    task for task in REGISTRY.tasks if task.family_id == "checksum-manifest"
)


def task_by_parameters(family: str, **values: object):
    for task in REGISTRY.tasks:
        if task.family_id != family:
            continue
        if all(getattr(task.parameters, key) == value for key, value in values.items()):
            return task
    raise AssertionError(f"task not found: {family} {values}")


class RecordFixtureCatalogTests(unittest.TestCase):
    def test_all_200_record_family_bundles_are_deterministic_and_unique(self) -> None:
        descriptors = []
        with mock.patch.object(
            subprocess, "run", side_effect=AssertionError("subprocess executed")
        ), mock.patch.object(
            subprocess, "Popen", side_effect=AssertionError("subprocess executed")
        ):
            for task in (*MANIFEST_TASKS, *CHECKSUM_TASKS):
                builder = (
                    build_manifest_copy_fixture_bundle
                    if task.family_id == "manifest-copy"
                    else build_checksum_manifest_fixture_bundle
                )
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                    bundle = builder(task, profile)
                    validate_executable_fixture_bundle(bundle)
                    self.assertEqual(bundle, builder(task, profile))
                    self.assertEqual(
                        bundle.profile_sha256,
                        profile.profile_sha256,
                    )
                    self.assertEqual(
                        bundle.descriptor.task_contract_sha256,
                        task.task_contract_sha256,
                    )
                    descriptors.append(bundle.descriptor)
        self.assertEqual(len(descriptors), 200)
        self.assertEqual(len({item.fixture_id for item in descriptors}), 200)
        self.assertEqual(len({item.fixture_sha256 for item in descriptors}), 200)

    def test_manifest_collision_policies_have_hand_checked_tree_outcomes(self) -> None:
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        unique_paths = {
            "output/unique/universal.txt",
            "output/unique/all-readable-only.bin",
            "output/unique/txt-only.txt",
            "output/unique/selected-only.bin",
            "output/unique/digest-only.bin",
        }
        expected_paths = {
            "reject-collision": unique_paths,
            "first-record": unique_paths | {
                "output/identical/result.txt",
                "output/shared/result.txt",
            },
            "last-record": unique_paths | {
                "output/identical/result.txt",
                "output/shared/result.txt",
            },
            "identical-bytes-only": unique_paths | {
                "output/identical/result.txt",
            },
            "utf8-smallest-source": unique_paths | {
                "output/identical/result.txt",
                "output/shared/result.txt",
            },
        }
        for policy, paths in expected_paths.items():
            task = task_by_parameters(
                "manifest-copy",
                selector="all-readable",
                collision_policy=policy,
            )
            bundle = build_manifest_copy_fixture_bundle(task, profile)
            outputs = {item.path: item.content for item in bundle.oracle.outputs}
            self.assertEqual(set(outputs), paths)
            if policy == "first-record":
                self.assertEqual(outputs["output/shared/result.txt"], b"z collision choice\n")
            if policy == "last-record":
                self.assertEqual(outputs["output/shared/result.txt"], b"m collision choice\n")
            if policy == "utf8-smallest-source":
                self.assertEqual(outputs["output/shared/result.txt"], b"a collision choice\n")

    def test_manifest_selectors_change_results_from_parsed_manifest(self) -> None:
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[1]
        output_paths: dict[str, set[str]] = {}
        for selector in (
            "all-readable",
            "txt-suffix",
            "selected-true",
            "declared-sha256-matches",
        ):
            task = task_by_parameters(
                "manifest-copy",
                selector=selector,
                collision_policy="first-record",
            )
            bundle = build_manifest_copy_fixture_bundle(task, profile)
            output_paths[selector] = {
                output.path for output in bundle.oracle.outputs
            }
            manifest = next(
                item
                for item in bundle.definition.inputs
                if item.path == "input/copy-map.jsonl"
            )
            self.assertIn(b"{malformed-json", manifest.content)
        self.assertEqual(len(output_paths["all-readable"]), 7)
        self.assertEqual(
            output_paths["txt-suffix"] - {
                "output/shared/result.txt",
                "output/identical/result.txt",
            },
            {"output/unique/universal.txt", "output/unique/txt-only.txt"},
        )
        self.assertEqual(
            output_paths["selected-true"] - {
                "output/shared/result.txt",
                "output/identical/result.txt",
            },
            {"output/unique/universal.txt", "output/unique/selected-only.bin"},
        )
        self.assertEqual(
            output_paths["declared-sha256-matches"] - {
                "output/shared/result.txt",
                "output/identical/result.txt",
            },
            {"output/unique/universal.txt", "output/unique/digest-only.bin"},
        )
        self.assertEqual(len({frozenset(paths) for paths in output_paths.values()}), 4)

    def test_every_selector_discriminates_all_five_collision_policies(self) -> None:
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        for selector in (
            "all-readable",
            "txt-suffix",
            "selected-true",
            "declared-sha256-matches",
        ):
            outcomes = []
            for policy in (
                "reject-collision",
                "first-record",
                "last-record",
                "identical-bytes-only",
                "utf8-smallest-source",
            ):
                task = task_by_parameters(
                    "manifest-copy",
                    selector=selector,
                    collision_policy=policy,
                )
                bundle = build_manifest_copy_fixture_bundle(task, profile)
                outcomes.append(
                    tuple(
                        (output.path, output.content)
                        for output in bundle.oracle.outputs
                    )
                )
            with self.subTest(selector=selector):
                self.assertEqual(len(set(outcomes)), 5)

    def test_checksum_layouts_derive_the_same_reference_records(self) -> None:
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        outputs = []
        for layout in (
            "json-object-lines",
            "json-array-lines",
            "rfc4180-csv",
            "nul-triplets",
        ):
            task = task_by_parameters(
                "checksum-manifest",
                layout=layout,
                policy="strict-kind-digest-and-mode",
            )
            bundle = build_checksum_manifest_fixture_bundle(task, profile)
            outputs.append(bundle.oracle.outputs[0].content)
        self.assertEqual(len(set(outputs)), 1)
        rows = [json.loads(line) for line in outputs[0].decode("utf-8").splitlines()]
        statuses: dict[str, list[str]] = {}
        for row in rows:
            statuses.setdefault(row["path"], []).append(row["status"])
        self.assertEqual(statuses["space name.txt"], ["ok", "checksum_mismatch"])
        self.assertEqual(
            statuses["한글 자료.bin"],
            ["checksum_and_mode_mismatch", "mode_mismatch"],
        )
        self.assertEqual(statuses['quoted,"asset".bin'], ["ok"])
        self.assertEqual(statuses["directory"], ["directory"])
        self.assertEqual(statuses["link-to-first"], ["symlink"])
        self.assertEqual(statuses["missing.file"], ["missing"])
        self.assertEqual(statuses["unreadable.bin"], ["unreadable"])

        csv_task = task_by_parameters(
            "checksum-manifest",
            layout="rfc4180-csv",
            policy="strict-kind-digest-and-mode",
        )
        csv_bundle = build_checksum_manifest_fixture_bundle(csv_task, profile)
        manifest = next(
            item
            for item in csv_bundle.definition.inputs
            if item.path == "input/manifest.data"
        )
        self.assertIn(b'"quoted,""asset"".bin"', manifest.content)

    def test_mode_only_does_not_read_mode_unreadable_asset(self) -> None:
        task = task_by_parameters(
            "checksum-manifest",
            layout="json-object-lines",
            policy="mode-only",
        )
        bundle = build_checksum_manifest_fixture_bundle(
            task, PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[-1]
        )
        rows = [
            json.loads(line)
            for line in bundle.oracle.outputs[0].content.decode("utf-8").splitlines()
        ]
        unreadable = [row for row in rows if row["path"] == "unreadable.bin"]
        self.assertEqual(unreadable, [{"path": "unreadable.bin", "status": "ok"}])

    def test_every_digest_and_mode_policy_exercises_mode_mismatch(self) -> None:
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        for policy in (
            "digest-and-mode",
            "readable-digest-and-mode",
            "strict-kind-digest-and-mode",
        ):
            task = task_by_parameters(
                "checksum-manifest",
                layout="json-object-lines",
                policy=policy,
            )
            bundle = build_checksum_manifest_fixture_bundle(task, profile)
            statuses = {
                json.loads(line)["status"]
                for line in bundle.oracle.outputs[0].content.decode("utf-8").splitlines()
            }
            with self.subTest(policy=policy):
                self.assertIn("mode_mismatch", statuses)

    def test_wrong_family_or_profile_type_fails_closed(self) -> None:
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        with self.assertRaises(ExecutableFixtureRecordError):
            build_manifest_copy_fixture_bundle(CHECKSUM_TASKS[0], profile)
        with self.assertRaises(ExecutableFixtureRecordError):
            build_checksum_manifest_fixture_bundle(MANIFEST_TASKS[0], profile)
        with self.assertRaises(ExecutableFixtureRecordError):
            build_manifest_copy_fixture_bundle(
                MANIFEST_TASKS[0], object()  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
