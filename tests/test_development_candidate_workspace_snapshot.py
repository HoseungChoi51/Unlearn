from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.development_candidate_workspace_snapshot import (  # noqa: E402
    DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_COMPONENT_BYTES,
    DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_DEPTH,
    DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_ENTRIES,
    DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_PATH_BYTES,
    DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_REGULAR_BYTES,
    DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_TOTAL_PAYLOAD_BYTES,
    DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_MAGIC,
    DEVELOPMENT_CANDIDATE_WORKSPACE_OUTPUT_PROJECTION_SCOPE,
    DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_VERSION,
    DevelopmentCandidateWorkspaceComparison,
    DevelopmentCandidateWorkspaceEntry,
    DevelopmentCandidateWorkspaceEntryType,
    DevelopmentCandidateWorkspaceSnapshot,
    DevelopmentCandidateWorkspaceSnapshotError,
    canonical_development_candidate_workspace_snapshot_record_bytes,
    compare_development_candidate_workspace_snapshot_to_handle,
    parse_development_candidate_workspace_snapshot,
)
from cbds.executable_workspace import (  # noqa: E402
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
    materialize_fixture,
)


HEADER = struct.Struct("<8sII")
ENTRY = struct.Struct("<B3sIIQ")


RawEntry = tuple[int, int, bytes, bytes]


def archive(
    entries: tuple[RawEntry, ...],
    *,
    magic: bytes = DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_MAGIC,
    version: int = DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_VERSION,
    count: int | None = None,
    trailing: bytes = b"",
) -> bytes:
    payload = bytearray(HEADER.pack(magic, version, len(entries) if count is None else count))
    for kind, mode, path, body in entries:
        payload.extend(ENTRY.pack(kind, b"\0\0\0", mode, len(path), len(body)))
        payload.extend(path)
        payload.extend(body)
    payload.extend(trailing)
    return bytes(payload)


def sample_raw_entries() -> tuple[RawEntry, ...]:
    # Component order is bytewise DFS preorder: a, a/z, a-, link.
    return (
        (1, 0o755, b"", b""),
        (1, 0o755, b"a", b""),
        (2, 0o640, b"a/z", b"private-answer\n"),
        (2, 0o600, b"a-", b"x"),
        (3, 0o777, b"link", b"a/z"),
    )


def parsed_sample() -> DevelopmentCandidateWorkspaceSnapshot:
    return parse_development_candidate_workspace_snapshot(archive(sample_raw_entries()))


def filesystem_archive(root: Path) -> bytes:
    records: list[RawEntry] = []

    def visit(path: Path, relative: bytes) -> None:
        metadata = os.lstat(path)
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            records.append((1, mode, relative, b""))
            children = sorted(
                os.scandir(path), key=lambda item: item.name.encode("utf-8")
            )
            for child in children:
                name = child.name.encode("utf-8")
                if not relative and name == b"input":
                    continue
                child_relative = name if not relative else relative + b"/" + name
                visit(Path(child.path), child_relative)
        elif stat.S_ISREG(metadata.st_mode):
            records.append((2, mode, relative, path.read_bytes()))
        elif stat.S_ISLNK(metadata.st_mode):
            records.append((3, mode, relative, os.readlink(path).encode("utf-8")))
        else:  # pragma: no cover - test fixtures construct only supported kinds
            raise AssertionError("unsupported test filesystem object")

    visit(root, b"")
    return archive(tuple(records))


class CanonicalArchiveTests(unittest.TestCase):
    def test_valid_archive_exposes_immutable_typed_entries_and_hashes(self) -> None:
        raw = archive(sample_raw_entries())
        snapshot = parse_development_candidate_workspace_snapshot(raw)

        self.assertEqual(snapshot.entry_count, 5)
        self.assertEqual(snapshot.archive_sha256, sha256(raw).hexdigest())
        self.assertEqual(snapshot.archive_bytes, len(raw))
        self.assertEqual(
            [entry.kind for entry in snapshot.entries],
            ["directory", "directory", "file", "file", "symlink"],
        )
        regular = snapshot.entries[2]
        self.assertEqual(regular.content_sha256, sha256(b"private-answer\n").hexdigest())
        self.assertEqual(regular.payload_bytes, len(b"private-answer\n"))
        self.assertEqual(snapshot.entries[-1].symlink_target, "a/z")
        self.assertIsNone(snapshot.entries[-1].content_sha256)
        self.assertEqual(snapshot.entries[0].payload_sha256, sha256(b"").hexdigest())

        with self.assertRaises(FrozenInstanceError):
            regular.path = "changed"  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            snapshot.entries = ()  # type: ignore[misc]
        self.assertNotIn("private-answer", repr(regular))

    def test_raw_byte_free_record_is_digest_bearing_and_nonauthorizing(self) -> None:
        snapshot = parsed_sample()
        record = snapshot.to_answer_free_record()
        canonical = canonical_development_candidate_workspace_snapshot_record_bytes(
            snapshot
        )
        self.assertEqual(canonical, snapshot.canonical_answer_free_record_bytes())
        self.assertEqual(json.loads(canonical), record)
        self.assertEqual(
            record["archive_scope"],
            DEVELOPMENT_CANDIDATE_WORKSPACE_OUTPUT_PROJECTION_SCOPE,
        )
        core = dict(record)
        digest = core.pop("answer_free_record_sha256")
        encoded_core = json.dumps(
            core,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertEqual(digest, sha256(encoded_core).hexdigest())
        serialized = canonical.decode("utf-8")
        self.assertNotIn("private-answer", serialized)
        self.assertNotIn('"a/z"', json.dumps(record["entries"][-1]))
        self.assertIs(record["raw_payload_bytes_included"], False)
        self.assertIs(record["payload_digests_included"], True)
        self.assertIs(record["paths_modes_and_sizes_included"], True)
        self.assertIs(record["answer_confidentiality_established"], False)
        self.assertIs(record["sealed_boundary_reuse_eligible"], False)
        for field in (
            "candidate_execution_authorized",
            "scored_evaluation_eligible",
            "model_selection_eligible",
            "claim_pipeline_eligible",
            "claim_authorized",
        ):
            self.assertIs(record[field], False)

    def test_unicode_paths_are_strict_but_not_ascii_only(self) -> None:
        raw = archive(
            (
                (1, 0o755, b"", b""),
                (1, 0o755, "한글".encode(), b""),
                (2, 0o644, "한글/β.txt".encode(), b"ok"),
            )
        )
        snapshot = parse_development_candidate_workspace_snapshot(raw)
        self.assertEqual(snapshot.entries[-1].path, "한글/β.txt")

    def test_root_only_archive_is_valid(self) -> None:
        snapshot = parse_development_candidate_workspace_snapshot(
            archive(((1, 0o700, b"", b""),))
        )
        self.assertEqual(snapshot.entry_count, 1)

    def test_directory_and_regular_special_bits_are_preserved_but_symlink_is_linux_shape(self) -> None:
        snapshot = parse_development_candidate_workspace_snapshot(
            archive(
                (
                    (1, 0o1777, b"", b""),
                    (2, 0o6755, b"tool", b"x"),
                    (3, 0o777, b"tool-link", b"tool"),
                )
            )
        )
        self.assertEqual(snapshot.entries[0].mode, 0o1777)
        self.assertEqual(snapshot.entries[1].mode, 0o6755)
        with self.assertRaisesRegex(DevelopmentCandidateWorkspaceSnapshotError, "0777"):
            parse_development_candidate_workspace_snapshot(
                archive(((1, 0o755, b"", b""), (3, 0o755, b"link", b"target")))
            )


class WireRejectionTests(unittest.TestCase):
    def assert_rejected(self, raw: object, pattern: str | None = None) -> None:
        context = self.assertRaises(DevelopmentCandidateWorkspaceSnapshotError)
        with context:
            parse_development_candidate_workspace_snapshot(raw)  # type: ignore[arg-type]
        if pattern is not None:
            self.assertRegex(str(context.exception), pattern)

    def test_every_strict_prefix_is_rejected(self) -> None:
        raw = archive(sample_raw_entries())
        for length in range(len(raw)):
            with self.subTest(length=length):
                self.assert_rejected(raw[:length])

    def test_mutable_or_active_archive_types_are_rejected(self) -> None:
        raw = archive(sample_raw_entries())
        for value in (bytearray(raw), memoryview(raw), "CBDSWSN1"):
            with self.subTest(type=type(value).__name__):
                self.assert_rejected(value, "immutable bytes")

    def test_header_magic_version_count_and_trailing_bytes_are_exact(self) -> None:
        entries = sample_raw_entries()
        self.assert_rejected(archive(entries, magic=b"CBDSWSN0"), "magic")
        self.assert_rejected(archive(entries, version=0), "version")
        self.assert_rejected(archive(entries, version=2), "version")
        self.assert_rejected(archive(entries, count=0), "entry count")
        self.assert_rejected(
            archive(entries, count=DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_ENTRIES + 1),
            "entry count",
        )
        self.assert_rejected(archive(entries, count=len(entries) - 1), "trailing")
        self.assert_rejected(archive(entries, count=len(entries) + 1), "truncated")
        self.assert_rejected(archive(entries, trailing=b"\0"), "trailing")

    def test_entry_type_reserved_mode_and_lengths_fail_closed(self) -> None:
        root = bytearray(archive(((1, 0o755, b"", b""),)))
        unknown = bytearray(root)
        unknown[16] = 0
        self.assert_rejected(bytes(unknown), "type")
        unknown[16] = 4
        self.assert_rejected(bytes(unknown), "type")

        reserved = bytearray(root)
        reserved[17] = 1
        self.assert_rejected(bytes(reserved), "reserved")

        mode = bytearray(root)
        struct.pack_into("<I", mode, 20, 0o10000)
        self.assert_rejected(bytes(mode), "mode")

        path_length = bytearray(root)
        struct.pack_into(
            "<I", path_length, 24, DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_PATH_BYTES + 1
        )
        self.assert_rejected(bytes(path_length), "path")

        regular = bytearray(
            archive(((1, 0o755, b"", b""), (2, 0o644, b"a", b"x")))
        )
        second_header = 16 + 20
        struct.pack_into(
            "<Q",
            regular,
            second_header + 12,
            DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_REGULAR_BYTES + 1,
        )
        self.assert_rejected(bytes(regular), "payload")

    def test_directory_payload_and_kind_specific_limits_are_rejected(self) -> None:
        self.assert_rejected(
            archive(((1, 0o755, b"", b"x"),)), "payload"
        )
        oversized = b"x" * (DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_REGULAR_BYTES + 1)
        self.assert_rejected(
            archive(((1, 0o755, b"", b""), (2, 0o644, b"file", oversized))),
            "payload",
        )

    def test_cumulative_payload_limit_is_enforced_before_tree_acceptance(self) -> None:
        one = b"x" * DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_REGULAR_BYTES
        files = tuple(
            (2, 0o600, f"f{index:02d}".encode(), one)
            for index in range(
                DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_TOTAL_PAYLOAD_BYTES
                // DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_REGULAR_BYTES
                + 1
            )
        )
        self.assert_rejected(
            archive(((1, 0o755, b"", b""), *files)), "cumulative"
        )


class PathAndTreeRejectionTests(unittest.TestCase):
    def assert_bad_path(self, path: bytes, pattern: str = "path") -> None:
        with self.assertRaisesRegex(DevelopmentCandidateWorkspaceSnapshotError, pattern):
            parse_development_candidate_workspace_snapshot(
                archive(((1, 0o755, b"", b""), (2, 0o644, path, b"x")))
            )

    def test_paths_reject_nul_invalid_utf8_absolute_empty_dotdot_controls_and_staging(self) -> None:
        bad = (
            b"a\0b",
            b"\xff",
            b"/absolute",
            b"trailing/",
            b"a//b",
            b".",
            b"..",
            b"a/.",
            b"a/..",
            b"line\nbreak",
            b".cbds-stage-secret",
        )
        for path in bad:
            with self.subTest(path=path):
                self.assert_bad_path(path)

    def test_path_component_total_bytes_and_depth_are_independently_bounded(self) -> None:
        self.assert_bad_path(
            b"x" * (DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_COMPONENT_BYTES + 1),
            "component",
        )
        long_path = b"/".join(
            b"x" * 250
            for _ in range(
                DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_PATH_BYTES // 250 + 1
            )
        )
        self.assert_bad_path(long_path, "byte limit")
        deep = b"/".join(
            b"x" for _ in range(DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_DEPTH + 1)
        )
        self.assert_bad_path(deep, "depth")

    def test_exactly_one_leading_directory_root_is_required(self) -> None:
        cases = (
            ((2, 0o644, b"", b"x"),),
            ((3, 0o777, b"", b"target"),),
            ((1, 0o755, b"a", b""),),
            ((1, 0o755, b"", b""), (1, 0o755, b"", b"")),
        )
        for entries in cases:
            with self.subTest(entries=entries), self.assertRaises(
                DevelopmentCandidateWorkspaceSnapshotError
            ):
                parse_development_candidate_workspace_snapshot(archive(entries))

    def test_top_level_input_entry_and_every_input_descendant_are_rejected(self) -> None:
        cases = (
            (
                (1, 0o755, b"", b""),
                (1, 0o755, b"input", b""),
            ),
            (
                (1, 0o755, b"", b""),
                (1, 0o755, b"input", b""),
                (2, 0o000, b"input/locked", b"secret"),
            ),
        )
        for entries in cases:
            with self.subTest(entries=entries), self.assertRaisesRegex(
                DevelopmentCandidateWorkspaceSnapshotError,
                "exclude the top-level input",
            ):
                parse_development_candidate_workspace_snapshot(archive(entries))

        # Similar names are output-side paths, not the reserved input subtree.
        parse_development_candidate_workspace_snapshot(
            archive(
                (
                    (1, 0o755, b"", b""),
                    (2, 0o644, b"input-copy", b"ok"),
                )
            )
        )

    def test_duplicate_missing_parent_and_nondirectory_ancestor_are_rejected(self) -> None:
        cases = (
            (
                (1, 0o755, b"", b""),
                (2, 0o644, b"a", b"x"),
                (2, 0o644, b"a", b"y"),
            ),
            ((1, 0o755, b"", b""), (2, 0o644, b"a/b", b"x")),
            (
                (1, 0o755, b"", b""),
                (2, 0o644, b"a", b"x"),
                (2, 0o644, b"a/b", b"y"),
            ),
        )
        for entries in cases:
            with self.subTest(entries=entries), self.assertRaises(
                DevelopmentCandidateWorkspaceSnapshotError
            ):
                parse_development_candidate_workspace_snapshot(archive(entries))

    def test_preorder_is_component_bytewise_not_flat_path_sorting(self) -> None:
        valid = (
            (1, 0o755, b"", b""),
            (1, 0o755, b"a", b""),
            (2, 0o644, b"a/z", b"x"),
            (2, 0o644, b"a-", b"y"),
        )
        parse_development_candidate_workspace_snapshot(archive(valid))
        wrong_flat_order = (valid[0], valid[1], valid[3], valid[2])
        with self.assertRaisesRegex(
            DevelopmentCandidateWorkspaceSnapshotError, "preorder"
        ):
            parse_development_candidate_workspace_snapshot(archive(wrong_flat_order))

        wrong_siblings = (
            (1, 0o755, b"", b""),
            (2, 0o644, b"z", b"x"),
            (2, 0o644, b"a", b"y"),
        )
        with self.assertRaisesRegex(
            DevelopmentCandidateWorkspaceSnapshotError, "preorder"
        ):
            parse_development_candidate_workspace_snapshot(archive(wrong_siblings))

    def test_symlink_targets_are_raw_strict_safe_relative_utf8(self) -> None:
        bad_targets = (
            b"",
            b"\0",
            b"\xff",
            b"/outside",
            b".",
            b"..",
            b"a/../outside",
            b"a//b",
            b"line\nbreak",
            b".cbds-stage-target",
            b"x" * (DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_COMPONENT_BYTES + 1),
        )
        for target in bad_targets:
            with self.subTest(target=target), self.assertRaises(
                DevelopmentCandidateWorkspaceSnapshotError
            ):
                parse_development_candidate_workspace_snapshot(
                    archive(
                        (
                            (1, 0o755, b"", b""),
                            (3, 0o777, b"link", target),
                        )
                    )
                )


class RevalidationForgeryTests(unittest.TestCase):
    def test_entry_and_snapshot_revalidate_post_construction_mutation(self) -> None:
        snapshot = parsed_sample()
        entry = snapshot.entries[2]
        object.__setattr__(entry, "payload", bytearray(entry.payload))
        with self.assertRaises(DevelopmentCandidateWorkspaceSnapshotError):
            entry.to_answer_free_record()
        with self.assertRaises(DevelopmentCandidateWorkspaceSnapshotError):
            snapshot.to_answer_free_record()

        clean = parsed_sample()
        object.__setattr__(clean, "candidate_execution_authorized", True)
        with self.assertRaisesRegex(
            DevelopmentCandidateWorkspaceSnapshotError, "authority"
        ):
            clean.to_answer_free_record()

    def test_active_container_enum_and_helper_types_fail_closed(self) -> None:
        entry = DevelopmentCandidateWorkspaceEntry(
            DevelopmentCandidateWorkspaceEntryType.DIRECTORY, "", 0o755, b""
        )
        with self.assertRaises(DevelopmentCandidateWorkspaceSnapshotError):
            DevelopmentCandidateWorkspaceSnapshot(entries=[entry])  # type: ignore[arg-type]
        with self.assertRaises(DevelopmentCandidateWorkspaceSnapshotError):
            DevelopmentCandidateWorkspaceEntry(1, "", 0o755, b"")  # type: ignore[arg-type]
        with self.assertRaises(DevelopmentCandidateWorkspaceSnapshotError):
            canonical_development_candidate_workspace_snapshot_record_bytes(
                object()  # type: ignore[arg-type]
            )


class WorkspaceComparisonTests(unittest.TestCase):
    @staticmethod
    def definition() -> FixtureDefinition:
        return FixtureDefinition(
            fixture_id="fixture.snapshot-comparison",
            inputs=(
                InputFile("input/source.txt", b"alpha\n", 0o000),
                InputSymlink("input/source-link", "source.txt"),
            ),
            expected_files=(ExpectedFile("output/result.txt", 64, 0o644),),
        )

    @staticmethod
    def create_output(workspace: Path) -> None:
        output = workspace / "output"
        output.mkdir(mode=0o755)
        result = output / "result.txt"
        result.write_bytes(b"answer\n")
        os.chmod(result, 0o644)

    def test_exact_output_projection_compares_and_mints_no_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with materialize_fixture(self.definition(), workspace) as handle:
                self.create_output(workspace)
                snapshot = parse_development_candidate_workspace_snapshot(
                    filesystem_archive(workspace)
                )
                self.assertFalse(
                    any(
                        entry.path == "input" or entry.path.startswith("input/")
                        for entry in snapshot.entries
                    )
                )
                comparison = compare_development_candidate_workspace_snapshot_to_handle(
                    snapshot, handle
                )

        self.assertIsInstance(comparison, DevelopmentCandidateWorkspaceComparison)
        record = comparison.to_record()
        self.assertTrue(record["output_projection_matched"])
        self.assertTrue(record["stable_input_tree_observed"])
        self.assertFalse(record["input_projection_compared"])
        self.assertIs(record["raw_snapshot_payload_bytes_included"], False)
        self.assertIs(record["snapshot_payload_digests_included"], True)
        self.assertIs(record["answer_confidentiality_established"], False)
        self.assertIs(record["sealed_boundary_reuse_eligible"], False)
        for field in (
            "output_kind_compared",
            "output_mode_compared",
            "output_regular_size_compared",
            "output_regular_content_sha256_compared",
            "output_symlink_target_bytes_compared",
        ):
            self.assertIs(record[field], True)
        for field in (
            "mtime_ns_compared",
            "ownership_compared",
            "inode_identity_compared",
            "link_count_compared",
            "candidate_execution_authorized",
            "scored_evaluation_eligible",
            "model_selection_eligible",
            "claim_pipeline_eligible",
            "claim_authorized",
        ):
            self.assertIs(record[field], False)
        core = dict(record)
        digest = core.pop("comparison_sha256")
        encoded = json.dumps(
            core,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertEqual(digest, sha256(encoded).hexdigest())

    def test_content_mode_and_path_mismatches_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with materialize_fixture(self.definition(), workspace) as handle:
                self.create_output(workspace)
                raw = filesystem_archive(workspace)
                snapshot = parse_development_candidate_workspace_snapshot(raw)

                entries = list(snapshot.entries)
                index = next(
                    index
                    for index, entry in enumerate(entries)
                    if entry.path == "output/result.txt"
                )
                target = entries[index]
                entries[index] = DevelopmentCandidateWorkspaceEntry(
                    target.entry_type,
                    target.path,
                    target.mode,
                    b"forged\n",
                )
                forged_content = DevelopmentCandidateWorkspaceSnapshot(tuple(entries))
                with self.assertRaisesRegex(
                    DevelopmentCandidateWorkspaceSnapshotError, "content"
                ):
                    compare_development_candidate_workspace_snapshot_to_handle(
                        forged_content, handle
                    )

                entries = list(snapshot.entries)
                root = entries[0]
                entries[0] = DevelopmentCandidateWorkspaceEntry(
                    root.entry_type, root.path, root.mode ^ 0o001, root.payload
                )
                forged_mode = DevelopmentCandidateWorkspaceSnapshot(tuple(entries))
                with self.assertRaisesRegex(
                    DevelopmentCandidateWorkspaceSnapshotError, "root"
                ):
                    compare_development_candidate_workspace_snapshot_to_handle(
                        forged_mode, handle
                    )

                without_output = tuple(
                    entry
                    for entry in snapshot.entries
                    if entry.path != "output/result.txt"
                )
                missing_path = DevelopmentCandidateWorkspaceSnapshot(without_output)
                with self.assertRaisesRegex(
                    DevelopmentCandidateWorkspaceSnapshotError, "path set"
                ):
                    compare_development_candidate_workspace_snapshot_to_handle(
                        missing_path, handle
                    )

    def test_closed_active_and_forged_comparison_objects_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            handle = materialize_fixture(self.definition(), workspace)
            self.create_output(workspace)
            snapshot = parse_development_candidate_workspace_snapshot(
                filesystem_archive(workspace)
            )
            handle.close()
            with self.assertRaises(DevelopmentCandidateWorkspaceSnapshotError):
                compare_development_candidate_workspace_snapshot_to_handle(
                    snapshot, handle
                )
            with self.assertRaises(DevelopmentCandidateWorkspaceSnapshotError):
                compare_development_candidate_workspace_snapshot_to_handle(
                    object(), handle  # type: ignore[arg-type]
                )
            with self.assertRaises(DevelopmentCandidateWorkspaceSnapshotError):
                compare_development_candidate_workspace_snapshot_to_handle(
                    snapshot, object()  # type: ignore[arg-type]
                )

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with materialize_fixture(self.definition(), workspace) as live:
                self.create_output(workspace)
                clean_snapshot = parse_development_candidate_workspace_snapshot(
                    filesystem_archive(workspace)
                )
                comparison = compare_development_candidate_workspace_snapshot_to_handle(
                    clean_snapshot, live
                )
                for changes in (
                    {"output_projection_matched": False},
                    {"stable_input_tree_observed": False},
                    {"input_projection_compared": True},
                ):
                    with self.subTest(changes=changes), self.assertRaises(
                        DevelopmentCandidateWorkspaceSnapshotError
                    ):
                        replace(comparison, **changes)
                object.__setattr__(comparison, "claim_authorized", True)
                with self.assertRaisesRegex(
                    DevelopmentCandidateWorkspaceSnapshotError, "authority"
                ):
                    comparison.to_record()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
