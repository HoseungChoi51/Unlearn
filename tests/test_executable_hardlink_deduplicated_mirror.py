from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import tempfile
import unittest

from cbds.executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_hardlink_deduplicated_mirror import (
    HARDLINK_DEDUPLICATED_MIRROR_ALLOWED_TOOLS,
    HARDLINK_DEDUPLICATED_MIRROR_EQUIVALENCE_KEYS,
    HARDLINK_DEDUPLICATED_MIRROR_FAMILY_ID,
    HARDLINK_DEDUPLICATED_MIRROR_LEDGER_OUTPUT,
    HARDLINK_DEDUPLICATED_MIRROR_OWNER_POLICIES,
    HARDLINK_DEDUPLICATED_MIRROR_OUTPUT_ROOT,
    HardlinkDeduplicatedMirrorError,
    build_hardlink_deduplicated_mirror_fixture_bundle,
    build_hardlink_deduplicated_mirror_tasks,
    compute_hardlink_deduplicated_mirror_discrimination_sha256,
    derive_hardlink_deduplicated_mirror_state,
    materialize_hardlink_deduplicated_mirror_fixture,
    reference_hardlink_deduplicated_mirror_state,
    validate_hardlink_deduplicated_mirror_fixture_bundle,
    validate_hardlink_deduplicated_mirror_fixture_for_task_profile,
    verify_hardlink_deduplicated_mirror_fixture_bundle,
    verify_hardlink_deduplicated_mirror_fixture_for_task_profile,
    verify_hardlink_deduplicated_mirror_state,
    verify_hardlink_deduplicated_mirror_workspace,
)
from cbds.executable_workspace import InputHardlink


def _profile(profile_id: str):
    return next(
        item
        for item in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        if item.profile_id == profile_id
    )


def _task(tasks, key: str, policy: str):
    return next(
        item
        for item in tasks
        if item.parameters.equivalence_key == key
        and item.parameters.owner_policy == policy
    )


def _ensure_mode_0755(path: Path, workspace: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    current = path
    while current != workspace:
        current.chmod(0o755)
        current = current.parent


def _publish_exact_state(handle, bundle) -> None:
    """Materialize the trusted final answer with real physical hardlinks."""

    workspace = handle.workspace
    by_output = {item.path: item for item in bundle.oracle.outputs}
    groups: dict[str, list[str]] = {}
    for member in bundle.oracle.members:
        groups.setdefault(member.semantic_group_sha256, []).append(
            member.output_path
        )
    for paths in groups.values():
        paths.sort(key=str.encode)
        expected = by_output[paths[0]]
        target = workspace / paths[0]
        _ensure_mode_0755(target.parent, workspace)
        target.write_bytes(expected.content)
        target.chmod(expected.mode)
        stamp = expected.mtime_seconds
        if stamp is None:
            raise AssertionError("tree output lacks committed owner mtime")
        os.utime(
            target,
            ns=(stamp * 1_000_000_000, stamp * 1_000_000_000),
        )
        for relative in paths[1:]:
            linked = workspace / relative
            _ensure_mode_0755(linked.parent, workspace)
            os.link(target, linked)

    ledger = by_output[HARDLINK_DEDUPLICATED_MIRROR_LEDGER_OUTPUT]
    ledger_path = workspace / ledger.path
    _ensure_mode_0755(ledger_path.parent, workspace)
    ledger_path.write_bytes(ledger.content)
    ledger_path.chmod(ledger.mode)


class HardlinkDeduplicatedMirrorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = build_hardlink_deduplicated_mirror_tasks()
        cls.bundles = {
            (task.task_id, profile.profile_id):
            build_hardlink_deduplicated_mirror_fixture_bundle(task, profile)
            for task in cls.tasks
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        }

    def bundle(self, task, profile):
        return self.bundles[(task.task_id, profile.profile_id)]

    def test_exact_four_by_five_grid_and_public_boundary(self) -> None:
        self.assertEqual(
            HARDLINK_DEDUPLICATED_MIRROR_ALLOWED_TOOLS,
            ("cp", "find", "ln", "mkdir", "sha256sum", "sort", "stat"),
        )
        self.assertEqual(len(self.tasks), 20)
        self.assertEqual(
            {
                (
                    item.parameters.equivalence_key,
                    item.parameters.owner_policy,
                )
                for item in self.tasks
            },
            {
                (key, policy)
                for key in HARDLINK_DEDUPLICATED_MIRROR_EQUIVALENCE_KEYS
                for policy in HARDLINK_DEDUPLICATED_MIRROR_OWNER_POLICIES
            },
        )
        self.assertEqual(len({item.task_id for item in self.tasks}), 20)
        self.assertEqual(
            len({item.task_contract_sha256 for item in self.tasks}), 20
        )
        self.assertEqual(len({item.graph_sha256 for item in self.tasks}), 20)
        for item in self.tasks:
            self.assertEqual(
                item.family_id, HARDLINK_DEDUPLICATED_MIRROR_FAMILY_ID
            )
            self.assertTrue(item.public)
            self.assertFalse(item.sealed)
            self.assertFalse(item.candidate_execution_authorized)
            self.assertFalse(item.model_selection_eligible)
            self.assertFalse(item.claim_authorized)
            self.assertEqual(len(item.fixtures), 5)
            self.assertIn("cbds-hardlink-group-v2", item.prompt)
            self.assertNotIn("touch", item.prompt)
            item.__post_init__()

    def test_build_is_deterministic(self) -> None:
        self.assertEqual(
            build_hardlink_deduplicated_mirror_tasks(), self.tasks
        )
        digest = compute_hardlink_deduplicated_mirror_discrimination_sha256(
            self.tasks
        )
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(
            digest,
            "1a0c0d23bb262c1d94250a92574c89af6c6333da08d58be715e1b5d1f4940435",
        )

    def test_all_100_bundles_are_dual_engine_bound_and_answer_free(self) -> None:
        fixture_ids: set[str] = set()
        for task in self.tasks:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                bundle = self.bundle(task, profile)
                validate_hardlink_deduplicated_mirror_fixture_bundle(bundle)
                validate_hardlink_deduplicated_mirror_fixture_for_task_profile(
                    task, profile, bundle
                )
                self.assertTrue(
                    verify_hardlink_deduplicated_mirror_fixture_bundle(bundle)
                )
                self.assertTrue(
                    verify_hardlink_deduplicated_mirror_fixture_for_task_profile(
                        task, profile, bundle
                    )
                )
                primary = derive_hardlink_deduplicated_mirror_state(
                    bundle.definition, task.parameters
                )
                reference = reference_hardlink_deduplicated_mirror_state(
                    bundle.definition, task.parameters
                )
                self.assertEqual(primary, reference)
                self.assertEqual(
                    primary, (bundle.oracle.members, bundle.oracle.outputs)
                )
                self.assertTrue(
                    verify_hardlink_deduplicated_mirror_state(
                        bundle.definition,
                        task.parameters,
                        bundle.oracle.members,
                        bundle.oracle.outputs,
                    )
                )
                self.assertTrue(
                    any(
                        type(value) is InputHardlink
                        for value in bundle.definition.inputs
                    )
                )
                for expected in bundle.definition.expected_files:
                    if expected.path == HARDLINK_DEDUPLICATED_MIRROR_LEDGER_OUTPUT:
                        self.assertEqual(expected.required_link_count, 1)
                        self.assertEqual(expected.mode, 0o644)
                    else:
                        self.assertIsNone(expected.required_link_count)
                        self.assertIsNone(expected.mode)
                fixture_ids.add(bundle.descriptor.fixture_id)
        self.assertEqual(len(fixture_ids), 100)

    def test_partition_and_owner_probes_discriminate_every_cell(self) -> None:
        profile = _profile("spaces-unicode")
        expected_partitions = {
            "sha256": {
                ("key/a.txt", "key/b.log", "key/c.txt", "key/d.log")
            },
            "mode-and-sha256": {
                ("key/a.txt", "key/b.log"),
                ("key/c.txt", "key/d.log"),
            },
            "suffix-and-sha256": {
                ("key/a.txt", "key/c.txt"),
                ("key/b.log", "key/d.log"),
            },
            "declared-group-and-sha256": {
                ("key/a.txt", "key/d.log"),
                ("key/b.log", "key/c.txt"),
            },
        }
        expected_owner = {
            "smallest-path": "owner/a.dat",
            "largest-path": "owner/e.dat",
            "oldest-mtime": "owner/b.dat",
            "newest-mtime": "owner/d.dat",
            "manifest-priority": "owner/c.dat",
        }
        signatures: set[tuple[frozenset[tuple[str, ...]], str]] = set()
        for task in self.tasks:
            bundle = self.bundle(task, profile)
            groups: dict[str, list[str]] = {}
            owner = ""
            for member in bundle.oracle.members:
                if member.source.startswith("key/"):
                    groups.setdefault(
                        member.semantic_group_sha256, []
                    ).append(member.source)
                if member.source == "owner/a.dat":
                    owner = member.representative
            partition = {
                tuple(sorted(values, key=str.encode))
                for values in groups.values()
            }
            self.assertEqual(
                partition,
                expected_partitions[task.parameters.equivalence_key],
            )
            self.assertEqual(
                owner, expected_owner[task.parameters.owner_policy]
            )
            signatures.add((frozenset(partition), owner))
        self.assertEqual(len(signatures), 20)

    def test_all_100_trusted_materializations_verify(self) -> None:
        for task in self.tasks:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                bundle = self.bundle(task, profile)
                with tempfile.TemporaryDirectory() as temporary:
                    with materialize_hardlink_deduplicated_mirror_fixture(
                        task,
                        profile,
                        bundle,
                        Path(temporary) / "workspace",
                    ) as handle:
                        _publish_exact_state(handle, bundle)
                        self.assertTrue(
                            verify_hardlink_deduplicated_mirror_workspace(
                                task, profile, bundle, handle
                            ),
                            (task.parameters, profile.profile_id),
                        )

    def test_topology_split_and_external_link_mutants_fail(self) -> None:
        task = _task(self.tasks, "sha256", "smallest-path")
        profile = _profile("spaces-unicode")
        bundle = self.bundle(task, profile)
        group = next(
            [
                member
                for member in bundle.oracle.members
                if member.source.startswith("key/")
            ]
            for _ in (0,)
        )
        target_member = group[-1]

        with tempfile.TemporaryDirectory() as temporary:
            with materialize_hardlink_deduplicated_mirror_fixture(
                task,
                profile,
                bundle,
                Path(temporary) / "workspace",
            ) as handle:
                _publish_exact_state(handle, bundle)
                path = handle.workspace / target_member.output_path
                expected = next(
                    item
                    for item in bundle.oracle.outputs
                    if item.path == target_member.output_path
                )
                path.unlink()
                path.write_bytes(expected.content)
                path.chmod(expected.mode)
                os.utime(
                    path,
                    ns=(
                        expected.mtime_seconds * 1_000_000_000,
                        expected.mtime_seconds * 1_000_000_000,
                    ),
                )
                self.assertFalse(
                    verify_hardlink_deduplicated_mirror_workspace(
                        task, profile, bundle, handle
                    )
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with materialize_hardlink_deduplicated_mirror_fixture(
                task, profile, bundle, root / "workspace"
            ) as handle:
                _publish_exact_state(handle, bundle)
                os.link(
                    handle.workspace / target_member.output_path,
                    root / "outside-link",
                )
                self.assertFalse(
                    verify_hardlink_deduplicated_mirror_workspace(
                        task, profile, bundle, handle
                    )
                )

    def test_input_alias_and_ledger_mutants_fail(self) -> None:
        task = _task(
            self.tasks, "declared-group-and-sha256", "manifest-priority"
        )
        profile = _profile("symlinks-ordering")
        bundle = self.bundle(task, profile)
        member = next(
            item
            for item in bundle.oracle.members
            if item.source == "links/base.bin"
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_hardlink_deduplicated_mirror_fixture(
                task,
                profile,
                bundle,
                Path(temporary) / "workspace",
            ) as handle:
                _publish_exact_state(handle, bundle)
                output = handle.workspace / member.output_path
                output.unlink()
                os.link(
                    handle.workspace
                    / "input/source"
                    / member.representative,
                    output,
                )
                self.assertFalse(
                    verify_hardlink_deduplicated_mirror_workspace(
                        task, profile, bundle, handle
                    )
                )

        with tempfile.TemporaryDirectory() as temporary:
            with materialize_hardlink_deduplicated_mirror_fixture(
                task,
                profile,
                bundle,
                Path(temporary) / "workspace",
            ) as handle:
                _publish_exact_state(handle, bundle)
                parent = handle.workspace / "input/source/links"
                parent_metadata = parent.stat()
                base = parent / "base.bin"
                alias = parent / "copy.bin"
                old_inode = base.lstat().st_ino
                base.unlink()
                alias.unlink()
                replacement = handle.workspace / "replacement.bin"
                replacement.write_bytes(b"already-linked\n")
                replacement.chmod(0o604)
                os.utime(
                    replacement,
                    ns=(700_000_000_000, 700_000_000_000),
                )
                os.link(replacement, base)
                os.link(replacement, alias)
                replacement.unlink()
                os.utime(
                    parent,
                    ns=(
                        parent_metadata.st_atime_ns,
                        parent_metadata.st_mtime_ns,
                    ),
                )
                self.assertNotEqual(base.lstat().st_ino, old_inode)
                self.assertEqual(
                    handle.scan_inputs().entries,
                    handle.baseline.input_entries,
                )
                self.assertFalse(
                    verify_hardlink_deduplicated_mirror_workspace(
                        task, profile, bundle, handle
                    )
                )

        with tempfile.TemporaryDirectory() as temporary:
            with materialize_hardlink_deduplicated_mirror_fixture(
                task,
                profile,
                bundle,
                Path(temporary) / "workspace",
            ) as handle:
                _publish_exact_state(handle, bundle)
                ledger = handle.workspace / HARDLINK_DEDUPLICATED_MIRROR_LEDGER_OUTPUT
                ledger.write_bytes(ledger.read_bytes() + b"extra\n")
                ledger.chmod(0o644)
                self.assertFalse(
                    verify_hardlink_deduplicated_mirror_workspace(
                        task, profile, bundle, handle
                    )
                )

    def test_fail_closed_types_and_hash_tampering(self) -> None:
        task = self.tasks[0]
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        bundle = self.bundle(task, profile)
        self.assertFalse(
            verify_hardlink_deduplicated_mirror_fixture_bundle(object())
        )
        self.assertFalse(
            verify_hardlink_deduplicated_mirror_fixture_for_task_profile(
                object(), profile, bundle
            )
        )
        with self.assertRaises(HardlinkDeduplicatedMirrorError):
            replace(bundle.oracle, oracle_sha256="0" * 64)
        with self.assertRaises(HardlinkDeduplicatedMirrorError):
            replace(bundle, fixture_definition_sha256="0" * 64)


if __name__ == "__main__":
    unittest.main()
