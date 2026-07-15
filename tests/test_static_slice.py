from __future__ import annotations

from collections import Counter
from dataclasses import replace
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.static_slice import (  # noqa: E402
    MAX_OUTPUT_BYTES,
    MAX_TREE_DEPTH,
    MAX_TREE_ENTRY_BYTES,
    MAX_TREE_ENTRIES,
    MAX_TREE_TOTAL_BYTES,
    OUTPUT_RELATIVE_PATH,
    REQUIRED_EDGE_CASES,
    TASK_ID,
    TASK_PROMPT,
    FixtureDescriptor,
    FixtureVerificationError,
    MaterializationError,
    StaticSliceSuite,
)
import cbds.static_slice as static_slice  # noqa: E402


def failure_codes(result: object) -> set[str]:
    return {failure.code for failure in result.failures}  # type: ignore[attr-defined]


def write_reference(suite: StaticSliceSuite, instance: object) -> bytes:
    payload = suite.trusted_reference_output(instance)  # type: ignore[arg-type]
    (instance.workspace / OUTPUT_RELATIVE_PATH).write_bytes(payload)  # type: ignore[attr-defined]
    return payload


def materialize_first(
    suite: StaticSliceSuite, parent: Path, *, write_answer: bool = False
) -> object:
    instance = suite.materialize(suite.descriptors[0], parent / "workspace")
    if write_answer:
        write_reference(suite, instance)
    return instance


def walk_without_following(root: Path) -> list[Path]:
    paths: list[Path] = []

    def visit(directory: Path) -> None:
        children = sorted(os.scandir(directory), key=lambda item: os.fsencode(item.name))
        for child in children:
            path = Path(child.path)
            paths.append(path)
            metadata = child.stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                visit(path)

    visit(root)
    return paths


class DescriptorAndContractTests(unittest.TestCase):
    def test_contract_is_precise_and_static(self) -> None:
        self.assertEqual(TASK_ID, "static.active-labels-jsonl")
        for required_phrase in (
            "without following symbolic links",
            "JSON boolean `true`",
            "JSON string",
            "LC_ALL=C",
            "When your\nprogram exits",
            "must match its initial state",
            "no path other than the",
            "symlink or hard link",
        ):
            self.assertIn(required_phrase, TASK_PROMPT)

    def test_suite_has_at_least_five_opaque_deterministic_fixtures(self) -> None:
        first = StaticSliceSuite(seed=41)
        repeated = StaticSliceSuite(seed=41)
        changed = StaticSliceSuite(seed=42)

        self.assertGreaterEqual(len(first.descriptors), 5)
        self.assertEqual(first.descriptors, repeated.descriptors)
        self.assertEqual(first.suite_sha256, repeated.suite_sha256)
        self.assertNotEqual(first.descriptors, changed.descriptors)
        self.assertEqual(first.coverage_tags, REQUIRED_EDGE_CASES)
        self.assertEqual(len({item.fixture_id for item in first.descriptors}), 8)

        allowed_keys = {
            "schema_version",
            "task_id",
            "task_version",
            "fixture_id",
            "fixture_sha256",
        }
        for descriptor in first.descriptors:
            self.assertEqual(set(descriptor.to_record()), allowed_keys)
            self.assertRegex(descriptor.fixture_id, r"^fx-[0-9a-f]{20}$")
            self.assertRegex(descriptor.fixture_sha256, r"^[0-9a-f]{64}$")
            serialized = json.dumps(descriptor.to_record())
            self.assertNotIn("expected_output", serialized)
            self.assertNotIn("fixture_path", serialized)
            self.assertNotIn("case_tags", serialized)

    def test_default_contract_and_suite_have_cross_version_golden_hashes(self) -> None:
        suite = StaticSliceSuite()
        self.assertEqual(
            suite.contract_sha256,
            "7be44067c5012ea94f65f99cf4c242cdbb361606758b3a8178639ec788c38ba8",
        )
        self.assertEqual(
            suite.suite_sha256,
            "4e5a3040f708eb91dc2d9c44a4e97d74039650a8bf93fd08eee8d3835477ae34",
        )

    def test_descriptor_tuple_is_not_a_mutable_internal_container(self) -> None:
        suite = StaticSliceSuite()
        first = suite.descriptors
        second = suite.descriptors
        self.assertIsNot(first, second)
        self.assertIsInstance(first, tuple)

    def test_coverage_case_annotations_are_part_of_suite_identity(self) -> None:
        seed = 73
        original = StaticSliceSuite(seed=seed)
        definitions = static_slice._definitions(seed)
        changed_first = replace(
            definitions[0], cases=definitions[0].cases | {"identity-probe"}
        )
        with mock.patch.object(
            static_slice,
            "_definitions",
            return_value=(changed_first, *definitions[1:]),
        ):
            changed = StaticSliceSuite(seed=seed)
        self.assertNotEqual(
            original.descriptors[0].fixture_sha256,
            changed.descriptors[0].fixture_sha256,
        )
        self.assertNotEqual(original.suite_sha256, changed.suite_sha256)


class MaterializationTests(unittest.TestCase):
    def test_shared_ancestor_content_changes_do_not_change_its_identity(self) -> None:
        real_stat = os.stat
        root_descriptor: int | None = None
        with tempfile.TemporaryDirectory() as temporary:
            ancestor_name = Path(temporary).name

            def stat_with_changed_directory_metadata(
                path: object, *args: object, **kwargs: object
            ) -> object:
                metadata = real_stat(path, *args, **kwargs)
                if path != ancestor_name:
                    return metadata
                return SimpleNamespace(
                    st_dev=metadata.st_dev,
                    st_ino=metadata.st_ino,
                    st_mode=metadata.st_mode,
                    st_nlink=metadata.st_nlink + 1,
                    st_size=metadata.st_size + 1,
                    st_mtime_ns=metadata.st_mtime_ns + 1,
                    st_ctime_ns=metadata.st_ctime_ns + 1,
                )

            try:
                with mock.patch.object(
                    static_slice.os,
                    "stat",
                    side_effect=stat_with_changed_directory_metadata,
                ):
                    root_descriptor, _ = (
                        static_slice._open_or_create_workspace_no_follow(
                            Path(temporary) / "workspace"
                        )
                    )
            finally:
                if root_descriptor is not None:
                    os.close(root_descriptor)

    def test_effective_readability_uses_one_posix_access_class(self) -> None:
        def metadata(mode: int, *, uid: int, gid: int) -> os.stat_result:
            return os.stat_result(
                (stat.S_IFREG | mode, 1, 1, 1, uid, gid, 0, 0, 0, 0)
            )

        with mock.patch.object(
            static_slice.os, "geteuid", return_value=1000
        ), mock.patch.object(
            static_slice.os, "getegid", return_value=2000
        ), mock.patch.object(
            static_slice.os, "getgroups", return_value=[2000, 3000]
        ):
            # Owner class wins even if group/other grant read access.
            self.assertFalse(
                static_slice._regular_is_effectively_readable(
                    metadata(0o004, uid=1000, gid=4000)
                )
            )
            self.assertFalse(
                static_slice._regular_is_effectively_readable(
                    metadata(0o040, uid=1000, gid=3000)
                )
            )
            self.assertTrue(
                static_slice._regular_is_effectively_readable(
                    metadata(0o400, uid=1000, gid=4000)
                )
            )
            # A matching supplementary group similarly excludes other bits.
            self.assertTrue(
                static_slice._regular_is_effectively_readable(
                    metadata(0o040, uid=4000, gid=3000)
                )
            )
            self.assertFalse(
                static_slice._regular_is_effectively_readable(
                    metadata(0o004, uid=4000, gid=3000)
                )
            )
            self.assertTrue(
                static_slice._regular_is_effectively_readable(
                    metadata(0o004, uid=4000, gid=5000)
                )
            )

        with mock.patch.object(static_slice.os, "geteuid", return_value=0):
            self.assertTrue(
                static_slice._regular_is_effectively_readable(
                    metadata(0o000, uid=1000, gid=3000)
                )
            )

    @unittest.skipIf(
        os.geteuid() == 0,
        "root can pathname-read every regular file regardless of read bits",
    )
    def test_reference_keeps_any_read_bit_semantics_via_pinned_files(self) -> None:
        pinned: list[static_slice._PinnedRegular] = []
        root_descriptor: int | None = None
        with tempfile.TemporaryDirectory() as temporary:
            try:
                root_descriptor, _ = (
                    static_slice._open_or_create_workspace_no_follow(
                        Path(temporary) / "workspace"
                    )
                )
                static_slice._ensure_relative_directory(
                    root_descriptor, static_slice.PurePosixPath("input")
                )
                definitions = (
                    (
                        "input/owner-other.jsonl",
                        b'{"active":true,"label":"other-bit"}\n',
                        0o004,
                    ),
                    (
                        "input/owner-group.jsonl",
                        b'{"active":true,"label":"group-bit"}\n',
                        0o040,
                    ),
                )
                for path, payload, mode in definitions:
                    retained = static_slice._write_relative_file(
                        root_descriptor,
                        static_slice.PurePosixPath(path),
                        payload,
                        mode,
                    )
                    self.assertIsNotNone(retained)
                    if retained is not None:
                        pinned.append(retained)

                output = static_slice._reference_output_descriptor(
                    root_descriptor,
                    pinned_regulars={item.path: item for item in pinned},
                )
                self.assertEqual(output, b"group-bit\nother-bit\n")
                for item in pinned:
                    self.assertGreaterEqual(item.descriptor, 0)
            finally:
                static_slice._close_pinned_regulars(pinned)
                if root_descriptor is not None:
                    os.close(root_descriptor)

        self.assertEqual([item.descriptor for item in pinned], [-1, -1])

    def test_materialization_requires_empty_real_workspace(self) -> None:
        suite = StaticSliceSuite()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            occupied = root / "occupied"
            occupied.mkdir()
            (occupied / "user-file").write_text("preserve me", encoding="utf-8")
            with self.assertRaisesRegex(MaterializationError, "must be empty"):
                suite.materialize(suite.descriptors[0], occupied)
            self.assertEqual(
                (occupied / "user-file").read_text(encoding="utf-8"), "preserve me"
            )

            target = root / "target"
            target.mkdir()
            symlink = root / "workspace-link"
            symlink.symlink_to(target, target_is_directory=True)
            with self.assertRaises(MaterializationError):
                suite.materialize(suite.descriptors[0], symlink)
            self.assertEqual(list(target.iterdir()), [])

            real_parent = root / "real-parent"
            real_parent.mkdir()
            parent_symlink = root / "parent-link"
            parent_symlink.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaises(MaterializationError):
                suite.materialize(suite.descriptors[0], parent_symlink / "child")
            self.assertEqual(list(real_parent.iterdir()), [])

    def test_workspace_swap_cannot_redirect_materialization_to_symlink_victim(self) -> None:
        suite = StaticSliceSuite()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            parked = root / "parked"
            victim = root / "victim"
            victim.mkdir()
            original_write = os.write
            swapped = False

            def racing_write(descriptor: int, payload: bytes) -> int:
                nonlocal swapped
                if not swapped:
                    swapped = True
                    workspace.rename(parked)
                    workspace.symlink_to(victim, target_is_directory=True)
                return original_write(descriptor, payload)

            with mock.patch.object(
                static_slice.os, "write", side_effect=racing_write
            ):
                with self.assertRaises(MaterializationError):
                    suite.materialize(suite.descriptors[0], workspace)

            self.assertTrue(swapped)
            self.assertEqual(list(victim.iterdir()), [])
            self.assertFalse((victim / "input" / "basic.jsonl").exists())

    def test_unknown_and_forged_descriptors_are_rejected(self) -> None:
        suite = StaticSliceSuite()
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(MaterializationError, "unknown fixture"):
                suite.materialize("fx-does-not-exist", Path(temporary) / "one")
            forged = replace(suite.descriptors[0], fixture_sha256="0" * 64)
            with self.assertRaisesRegex(MaterializationError, "commitment"):
                suite.materialize(forged, Path(temporary) / "two")

    def test_materialized_suite_really_contains_every_claimed_edge_case(self) -> None:
        suite = StaticSliceSuite(seed=19)
        facts: set[str] = set()
        all_selected_labels: list[bytes] = []
        duplicate_candidates: list[bytes] = []
        at_least_one_unsorted_fixture = False

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, descriptor in enumerate(suite.descriptors):
                instance = suite.materialize(descriptor, root / str(index))
                fixture_labels: list[bytes] = []
                for path in walk_without_following(instance.workspace / "input"):
                    relative_parts = path.relative_to(instance.workspace / "input").parts
                    name = path.name
                    metadata = path.lstat()
                    if any(" " in part for part in relative_parts):
                        facts.add("spaces")
                    if any(part.startswith("-") for part in relative_parts):
                        facts.add("leading_dash")
                    if any(any(character in part for character in "*?[") for part in relative_parts):
                        facts.add("glob_characters")
                    if any(any(ord(character) > 127 for character in part) for part in relative_parts):
                        facts.add("unicode")
                    if stat.S_ISLNK(metadata.st_mode):
                        facts.add("symlink_decoy")
                        continue
                    if not stat.S_ISREG(metadata.st_mode):
                        continue
                    mode = stat.S_IMODE(metadata.st_mode)
                    if not mode & 0o444:
                        facts.add("permission_decoy")
                        continue
                    payload = path.read_bytes()
                    if not payload:
                        facts.add("empty_input")
                    if any(byte >= 0x80 for byte in payload):
                        facts.add("unicode")
                    if not name.endswith(".jsonl"):
                        continue
                    for line in payload.splitlines():
                        if not line:
                            continue
                        value = json.loads(line)
                        if (
                            isinstance(value, dict)
                            and value.get("active") is True
                            and isinstance(value.get("label"), str)
                        ):
                            encoded = value["label"].encode("utf-8")
                            fixture_labels.append(encoded)
                            duplicate_candidates.append(encoded)
                            all_selected_labels.append(encoded)
                if fixture_labels != sorted(set(fixture_labels)):
                    at_least_one_unsorted_fixture = True

            if any(count > 1 for count in Counter(duplicate_candidates).values()):
                facts.add("duplicate_records")
            if at_least_one_unsorted_fixture:
                facts.add("ordering_variation")

        self.assertTrue(all_selected_labels)
        self.assertEqual(facts, REQUIRED_EDGE_CASES)

    def test_each_trusted_reference_passes_and_verification_is_repeatable(self) -> None:
        suite = StaticSliceSuite()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, descriptor in enumerate(suite.descriptors):
                with self.subTest(fixture=descriptor.fixture_id):
                    instance = suite.materialize(descriptor, root / str(index))
                    reference = write_reference(suite, instance)
                    self.assertLessEqual(len(reference), MAX_OUTPUT_BYTES)
                    first = suite.verify(instance)
                    second = suite.verify(instance)
                    self.assertTrue(first.passed, first.to_record())
                    self.assertEqual(first, second)
                    self.assertEqual(first.failures, ())
                    self.assertIsNotNone(first.output_sha256)

    def test_instance_cannot_be_verified_by_a_different_seeded_suite(self) -> None:
        suite = StaticSliceSuite(seed=1)
        other = StaticSliceSuite(seed=2)
        with tempfile.TemporaryDirectory() as temporary:
            instance = suite.materialize(suite.descriptors[0], temporary)
            with self.assertRaisesRegex(FixtureVerificationError, "another suite"):
                other.verify(instance)


class VerifierMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.suite = StaticSliceSuite(seed=101)

    def test_wrong_sort_order_is_killed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            instance = materialize_first(self.suite, Path(temporary))
            expected = self.suite.trusted_reference_output(instance)
            labels = expected[:-1].split(b"\n")
            self.assertGreaterEqual(len(labels), 2)
            (instance.workspace / OUTPUT_RELATIVE_PATH).write_bytes(
                b"\n".join(reversed(labels)) + b"\n"
            )
            result = self.suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("output_not_c_sorted", failure_codes(result))
        self.assertIn("output_labels_mismatch", failure_codes(result))

    def test_missing_deduplication_is_killed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            instance = materialize_first(self.suite, Path(temporary))
            expected = self.suite.trusted_reference_output(instance)
            labels = expected[:-1].split(b"\n")
            duplicated = sorted(labels + [labels[0]])
            (instance.workspace / OUTPUT_RELATIVE_PATH).write_bytes(
                b"\n".join(duplicated) + b"\n"
            )
            result = self.suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("output_not_unique", failure_codes(result))
        self.assertIn("output_labels_mismatch", failure_codes(result))

    def test_missing_output_is_killed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            instance = materialize_first(self.suite, Path(temporary))
            result = self.suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("output_missing", failure_codes(result))
        self.assertIsNone(result.observed_label_count)

    def test_symlink_output_is_killed_without_following_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            instance = materialize_first(self.suite, Path(temporary))
            (instance.workspace / OUTPUT_RELATIVE_PATH).symlink_to("input/basic.jsonl")
            result = self.suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("output_not_regular", failure_codes(result))

    def test_output_replacement_during_read_cannot_escape_or_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            instance = materialize_first(self.suite, root, write_answer=True)
            output = instance.workspace / OUTPUT_RELATIVE_PATH
            victim = root / "outside-secret.txt"
            victim.write_bytes(self.suite.trusted_reference_output(instance))
            original_read = os.read
            swapped = False

            def racing_read(descriptor: int, size: int) -> bytes:
                nonlocal swapped
                if not swapped:
                    try:
                        target = Path(
                            f"/proc/self/fd/{descriptor}"
                        ).resolve(strict=True)
                    except OSError:
                        target = None
                    if target == output:
                        swapped = True
                        output.unlink()
                        output.symlink_to(victim)
                return original_read(descriptor, size)

            with mock.patch.object(
                static_slice.os, "read", side_effect=racing_read
            ):
                result = self.suite.verify(instance)
        self.assertTrue(swapped)
        self.assertFalse(result.passed)
        self.assertIn("output_read_error", failure_codes(result))

    def test_input_replacement_during_scan_is_detected_without_following(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            instance = materialize_first(self.suite, root, write_answer=True)
            source = instance.workspace / "input" / "basic.jsonl"
            victim = root / "outside-secret.jsonl"
            victim.write_bytes(b'SEALED_FIXTURE_SECRET_DO_NOT_READ\n')
            original_read = os.read
            swapped = False

            def racing_read(descriptor: int, size: int) -> bytes:
                nonlocal swapped
                if not swapped:
                    try:
                        target = Path(
                            f"/proc/self/fd/{descriptor}"
                        ).resolve(strict=True)
                    except OSError:
                        target = None
                    if target == source:
                        swapped = True
                        source.unlink()
                        source.symlink_to(victim)
                return original_read(descriptor, size)

            with mock.patch.object(
                static_slice.os, "read", side_effect=racing_read
            ):
                result = self.suite.verify(instance)
        self.assertTrue(swapped)
        self.assertFalse(result.passed)
        self.assertIn("tree_scan_error", failure_codes(result))
        self.assertIn("missing_input_path", failure_codes(result))

    def test_hardlinked_output_is_killed_and_input_link_count_is_protected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            instance = materialize_first(self.suite, Path(temporary))
            os.link(
                instance.workspace / "input" / "basic.jsonl",
                instance.workspace / OUTPUT_RELATIVE_PATH,
            )
            result = self.suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("output_hardlinked", failure_codes(result))
        self.assertIn("input_entry_changed", failure_codes(result))

    def test_input_content_mutation_is_killed_even_with_correct_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            instance = materialize_first(
                self.suite, Path(temporary), write_answer=True
            )
            source = instance.workspace / "input" / "basic.jsonl"
            source.write_bytes(source.read_bytes() + b"{}\n")
            result = self.suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("input_entry_changed", failure_codes(result))
        self.assertNotIn("output_labels_mismatch", failure_codes(result))

    def test_restored_transient_mode_change_matches_final_state_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            instance = materialize_first(
                self.suite, Path(temporary), write_answer=True
            )
            source = instance.workspace / "input" / "basic.jsonl"
            source.chmod(0o600)
            source.chmod(0o644)
            result = self.suite.verify(instance)
        self.assertTrue(result.passed, result.to_record())

    def test_verification_does_not_change_unreadable_fixture_inode(self) -> None:
        suite = StaticSliceSuite(seed=101)
        with tempfile.TemporaryDirectory() as temporary:
            instance = suite.materialize(
                suite.descriptors[5], Path(temporary) / "workspace"
            )
            write_reference(suite, instance)
            locked = instance.workspace / "input" / "locked.jsonl"
            pinned = next(
                item
                for item in instance._pinned_regulars
                if item.path == "input/locked.jsonl"
            )
            before_stat = locked.stat(follow_symlinks=False)
            before = (
                before_stat.st_dev,
                before_stat.st_ino,
                stat.S_IMODE(before_stat.st_mode),
                before_stat.st_nlink,
                before_stat.st_size,
                before_stat.st_mtime_ns,
                before_stat.st_ctime_ns,
            )
            before_bytes = os.pread(
                pinned.descriptor, before_stat.st_size, 0
            )

            first = suite.verify(instance)
            second = suite.verify(instance)

            after_stat = locked.stat(follow_symlinks=False)
            after = (
                after_stat.st_dev,
                after_stat.st_ino,
                stat.S_IMODE(after_stat.st_mode),
                after_stat.st_nlink,
                after_stat.st_size,
                after_stat.st_mtime_ns,
                after_stat.st_ctime_ns,
            )
            after_bytes = os.pread(pinned.descriptor, after_stat.st_size, 0)

        self.assertTrue(first.passed, first.to_record())
        self.assertEqual(first, second)
        self.assertEqual(before, after)
        self.assertEqual(before_bytes, after_bytes)

    def test_pinned_unreadable_fixture_detects_same_size_restored_metadata_mutation(
        self,
    ) -> None:
        suite = StaticSliceSuite(seed=101)
        with tempfile.TemporaryDirectory() as temporary:
            instance = suite.materialize(
                suite.descriptors[5], Path(temporary) / "workspace"
            )
            write_reference(suite, instance)
            locked = instance.workspace / "input" / "locked.jsonl"
            before = locked.stat(follow_symlinks=False)
            original = os.pread(
                next(
                    item.descriptor
                    for item in instance._pinned_regulars
                    if item.path == "input/locked.jsonl"
                ),
                before.st_size,
                0,
            )
            replacement = bytes(
                (byte ^ 1) if index == 0 else byte
                for index, byte in enumerate(original)
            )
            self.assertEqual(len(replacement), len(original))
            locked.chmod(0o600)
            locked.write_bytes(replacement)
            locked.chmod(0o000)
            os.utime(
                locked,
                ns=(before.st_atime_ns, before.st_mtime_ns),
                follow_symlinks=False,
            )

            result = suite.verify(instance)

        self.assertFalse(result.passed)
        self.assertIn("input_entry_changed", failure_codes(result))

    def test_extra_path_is_killed_even_with_correct_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            instance = materialize_first(
                self.suite, Path(temporary), write_answer=True
            )
            (instance.workspace / "scratch.tmp").write_text("extra", encoding="utf-8")
            result = self.suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("unexpected_path", failure_codes(result))

    def test_oversized_output_is_rejected_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            instance = materialize_first(self.suite, Path(temporary))
            (instance.workspace / OUTPUT_RELATIVE_PATH).write_bytes(
                b"x" * (MAX_OUTPUT_BYTES + 1)
            )
            result = self.suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("output_too_large", failure_codes(result))
        self.assertIsNone(result.output_sha256)

    def test_oversized_extra_tree_entry_is_detected_with_capped_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            instance = materialize_first(
                self.suite, Path(temporary), write_answer=True
            )
            huge_extra = instance.workspace / "huge-extra.sparse"
            with huge_extra.open("wb") as handle:
                handle.truncate(MAX_TREE_ENTRY_BYTES + 1)
            result = self.suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("unexpected_path", failure_codes(result))

    def test_tree_depth_is_bounded_without_recursive_verifier_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            instance = materialize_first(
                self.suite, Path(temporary), write_answer=True
            )
            directory = instance.workspace
            for _ in range(MAX_TREE_DEPTH):
                directory /= "d"
                directory.mkdir()
            result = self.suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("tree_scan_error", failure_codes(result))

    def test_tree_entry_count_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            instance = materialize_first(
                self.suite, Path(temporary), write_answer=True
            )
            extras = instance.workspace / "extras"
            extras.mkdir()
            for index in range(MAX_TREE_ENTRIES):
                (extras / f"entry-{index:05d}").touch()
            result = self.suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("tree_scan_error", failure_codes(result))

    def test_tree_aggregate_regular_bytes_are_bounded_without_reading(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            instance = materialize_first(
                self.suite, Path(temporary), write_answer=True
            )
            huge_extra = instance.workspace / "aggregate-limit.sparse"
            with huge_extra.open("wb") as handle:
                handle.truncate(MAX_TREE_TOTAL_BYTES + 1)
            result = self.suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("tree_scan_error", failure_codes(result))

    def test_removed_input_and_invalid_utf8_are_both_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            instance = materialize_first(self.suite, Path(temporary))
            (instance.workspace / "input" / "basic.jsonl").unlink()
            (instance.workspace / OUTPUT_RELATIVE_PATH).write_bytes(b"\xff\n")
            result = self.suite.verify(instance)
        self.assertFalse(result.passed)
        self.assertIn("missing_input_path", failure_codes(result))
        self.assertIn("output_not_utf8", failure_codes(result))
        self.assertIn("output_labels_mismatch", failure_codes(result))


class ResultSerializationTests(unittest.TestCase):
    def test_result_record_contains_machine_readable_failures(self) -> None:
        suite = StaticSliceSuite()
        with tempfile.TemporaryDirectory() as temporary:
            instance = suite.materialize(suite.descriptors[0], temporary)
            result = suite.verify(instance)
        record = result.to_record()
        self.assertFalse(record["passed"])
        self.assertEqual(record["failures"][0]["code"], "output_missing")
        json.dumps(record, allow_nan=False)


if __name__ == "__main__":
    unittest.main()
