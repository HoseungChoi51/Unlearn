from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import fcntl
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.development_runtime_fd_snapshot as fd_snapshot
from cbds.development_runtime_bundle import (
    DevelopmentRuntimeExecutable,
    build_development_runtime_bundle_manifest,
)
from cbds.development_runtime_fd_snapshot import (
    DevelopmentRuntimeFdSlot,
    DevelopmentRuntimeFdSnapshotError,
    snapshot_development_runtime_for_launch,
    verify_development_runtime_fd_snapshot_structure,
)
from cbds.development_runtime_materializer import (
    materialize_development_runtime_bundle,
)


def _minimal_static_elf() -> bytes:
    identity = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\0" * 8
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        2,
        62,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        1,
        0,
        0,
        0,
    )
    program = struct.pack(
        "<IIQQQQQQ",
        1,
        5,
        0,
        0,
        0,
        120,
        120,
        4096,
    )
    payload = identity + header + program
    if len(payload) != 120:
        raise AssertionError("test ELF layout changed")
    return payload


class _RuntimeCase:
    def __init__(self, root: Path) -> None:
        self.source = root / "source"
        self.source.mkdir()
        self.payload = _minimal_static_elf()
        self.regular = self.source / "runtime.bin"
        self.regular.write_bytes(self.payload)
        self.regular.chmod(0o555)
        self.alias = self.source / "tool"
        self.alias.symlink_to("runtime.bin")
        self.manifest = build_development_runtime_bundle_manifest(
            (
                DevelopmentRuntimeExecutable(
                    name="tool",
                    source_path=str(self.alias),
                    expected_sha256=sha256(self.payload).hexdigest(),
                ),
            ),
            allowed_source_roots=(str(self.source),),
            library_search_directories=(str(self.source),),
        )
        self.destination = root / "runtime-root"
        self.evidence = materialize_development_runtime_bundle(
            self.manifest,
            self.destination,
            expected_manifest_sha256=self.manifest["manifest_sha256"],
        )

    @property
    def materialized_regular(self) -> Path:
        return self.destination / self.regular.relative_to("/")

    def snapshot(self):
        return snapshot_development_runtime_for_launch(
            self.manifest,
            self.evidence,
            expected_manifest_sha256=self.manifest["manifest_sha256"],
        )


def _replace_file_bytes(path: Path, payload: bytes) -> None:
    path.chmod(0o755)
    path.write_bytes(payload)
    path.chmod(0o555)


def _all_record_keys(value: object) -> set[str]:
    keys: set[str] = set()
    if type(value) is dict:
        for key, nested in value.items():  # type: ignore[union-attr]
            keys.add(key)
            keys.update(_all_record_keys(nested))
    elif type(value) is list:
        for nested in value:  # type: ignore[union-attr]
            keys.update(_all_record_keys(nested))
    return keys


class _StrSubclass(str):
    pass


class _DictSubclass(dict):
    pass


class DevelopmentRuntimeFdSnapshotTests(unittest.TestCase):
    def test_real_snapshot_record_binds_projection_without_serializing_fds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            with case.snapshot() as snapshot:
                record = snapshot.to_record()
                regular = next(
                    item for item in snapshot.entries if item.kind == "regular"
                )
                symbolic = next(
                    item for item in snapshot.entries if item.kind == "symlink"
                )

                self.assertEqual(
                    snapshot.source_manifest_sha256,
                    case.manifest["manifest_sha256"],
                )
                self.assertEqual(
                    snapshot.source_evidence_sha256,
                    case.evidence.evidence_sha256,
                )
                self.assertEqual(
                    snapshot.source_projection_sha256,
                    case.evidence.projection_sha256,
                )
                self.assertEqual(snapshot.directory_count, len(snapshot.directories))
                self.assertEqual(snapshot.entry_count, len(snapshot.entries))
                self.assertEqual(snapshot.regular_file_count, 1)
                self.assertEqual(snapshot.symlink_count, 1)
                self.assertEqual(snapshot.regular_payload_bytes, len(case.payload))
                self.assertEqual(regular.content_sha256, sha256(case.payload).hexdigest())
                self.assertEqual(symbolic.symlink_target, "runtime.bin")
                self.assertEqual(record["snapshot_sha256"], snapshot.snapshot_sha256)
                self.assertTrue(verify_development_runtime_fd_snapshot_structure(snapshot))
                self.assertFalse(snapshot.closed)

                true_facts = (
                    "source_materialization_binding_verified",
                    "descriptor_relative_projection_verified",
                    "sealed_regular_payloads_verified",
                    "same_uid_snapshot_payload_mutation_resistant",
                    "independent_read_descriptor_available",
                    "symlink_projection_recorded",
                )
                false_boundaries = (
                    "memfd_mode_immutable",
                    "same_uid_materialized_tree_mutation_resistant",
                    "runtime_data_and_dlopen_closure_verified",
                    "namespace_runtime_closure_verified",
                    "fd_bound_launch_handoff",
                    "launch_eligible",
                    "candidate_execution_authorized",
                    "scored_evaluation_eligible",
                    "claim_pipeline_eligible",
                )
                for field in true_facts:
                    self.assertIs(record[field], True)
                for field in false_boundaries:
                    self.assertIs(record[field], False)

                keys = _all_record_keys(record)
                self.assertNotIn("_owned_descriptors", keys)
                self.assertNotIn("descriptor", keys)
                self.assertNotIn("fd", keys)
                self.assertNotIn("_owned_descriptors", repr(snapshot))
                json.dumps(record, sort_keys=True, allow_nan=False)
                with self.assertRaises(FrozenInstanceError):
                    snapshot.launch_eligible = True  # type: ignore[misc]

    def test_memfd_has_exact_seals_and_rejects_write_shrink_and_growth(self) -> None:
        required = (
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL
        )
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            with case.snapshot() as snapshot:
                path = snapshot.regular_slots[0].destination_path
                descriptor = snapshot.duplicate_regular_fd(path)
                try:
                    self.assertFalse(os.get_inheritable(descriptor))
                    self.assertEqual(
                        fcntl.fcntl(descriptor, fcntl.F_GET_SEALS), required
                    )
                    self.assertEqual(os.read(descriptor, len(case.payload)), case.payload)
                    with self.assertRaises(OSError):
                        os.open(
                            f"/proc/self/fd/{descriptor}",
                            os.O_RDWR | os.O_CLOEXEC,
                        )
                    for operation in (
                        lambda: os.write(descriptor, b"x"),
                        lambda: os.ftruncate(descriptor, len(case.payload) - 1),
                        lambda: os.ftruncate(descriptor, len(case.payload) + 1),
                        lambda: fcntl.fcntl(
                            descriptor,
                            fcntl.F_ADD_SEALS,
                            fcntl.F_SEAL_WRITE,
                        ),
                    ):
                        with self.subTest(operation=operation):
                            with self.assertRaises(OSError):
                                operation()
                finally:
                    os.close(descriptor)

    def test_duplicate_read_descriptors_have_independent_offsets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            with case.snapshot() as snapshot:
                path = snapshot.regular_slots[0].destination_path
                first = snapshot.duplicate_regular_fd(path)
                second = snapshot.duplicate_regular_fd(path)
                try:
                    self.assertEqual(os.read(first, 13), case.payload[:13])
                    self.assertEqual(os.lseek(first, 0, os.SEEK_CUR), 13)
                    self.assertEqual(os.lseek(second, 0, os.SEEK_CUR), 0)
                    self.assertEqual(os.read(second, len(case.payload)), case.payload)
                    self.assertEqual(os.lseek(first, 0, os.SEEK_CUR), 13)
                finally:
                    os.close(first)
                    os.close(second)

    def test_source_and_materialized_mutation_after_snapshot_cannot_change_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            altered = bytes((case.payload[0] ^ 1,)) + case.payload[1:]
            with case.snapshot() as snapshot:
                path = snapshot.regular_slots[0].destination_path
                _replace_file_bytes(case.regular, altered)
                _replace_file_bytes(case.materialized_regular, altered)
                descriptor = snapshot.duplicate_regular_fd(path)
                try:
                    self.assertEqual(os.read(descriptor, len(case.payload)), case.payload)
                    self.assertEqual(
                        sha256(os.pread(descriptor, len(case.payload), 0)).hexdigest(),
                        snapshot.regular_slots[0].content_sha256,
                    )
                finally:
                    os.close(descriptor)

    def test_materialized_mutation_during_capture_rejects_and_closes_memfd(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            original = fd_snapshot._capture_regular_memfd
            captured: list[int] = []

            def capture_then_mutate(root_descriptor, entry):
                descriptor = original(root_descriptor, entry)
                captured.append(descriptor)
                altered = bytes((case.payload[0] ^ 1,)) + case.payload[1:]
                _replace_file_bytes(case.materialized_regular, altered)
                return descriptor

            with mock.patch.object(
                fd_snapshot,
                "_capture_regular_memfd",
                side_effect=capture_then_mutate,
            ):
                with self.assertRaises(DevelopmentRuntimeFdSnapshotError):
                    case.snapshot()
            self.assertEqual(len(captured), 1)
            with self.assertRaises(OSError):
                os.fstat(captured[0])

    def test_close_is_idempotent_rejects_copy_and_never_closes_reused_fd(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            snapshot = case.snapshot()
            owned = snapshot._owned_descriptors[0]
            self.assertIs(snapshot.closed, False)
            with self.assertRaises(DevelopmentRuntimeFdSnapshotError):
                copy.copy(snapshot)
            with self.assertRaises(DevelopmentRuntimeFdSnapshotError):
                copy.deepcopy(snapshot)

            snapshot.close()
            self.assertIs(snapshot.closed, True)
            with self.assertRaises(OSError):
                os.fstat(owned)
            with self.assertRaises(DevelopmentRuntimeFdSnapshotError):
                snapshot.duplicate_regular_fd(snapshot.regular_slots[0].destination_path)
            with self.assertRaises(DevelopmentRuntimeFdSnapshotError):
                snapshot.__enter__()

            replacement = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
            try:
                if replacement != owned:
                    os.dup2(replacement, owned, inheritable=False)
                    os.close(replacement)
                    replacement = owned
                snapshot.close()
                os.fstat(replacement)
            finally:
                os.close(replacement)

    def test_partial_construction_failure_closes_every_created_memfd(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            original_create = os.memfd_create
            created: list[int] = []

            def tracked_create(name, flags):
                descriptor = original_create(name, flags)
                created.append(descriptor)
                return descriptor

            with (
                mock.patch.object(
                    fd_snapshot.os,
                    "memfd_create",
                    side_effect=tracked_create,
                ),
                mock.patch.object(
                    fd_snapshot,
                    "_construct_snapshot",
                    side_effect=DevelopmentRuntimeFdSnapshotError("forced failure"),
                ),
            ):
                with self.assertRaisesRegex(
                    DevelopmentRuntimeFdSnapshotError,
                    "forced failure",
                ):
                    case.snapshot()
            self.assertEqual(len(created), 1)
            for descriptor in created:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_hostile_types_and_forged_metadata_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            with self.assertRaises(DevelopmentRuntimeFdSnapshotError):
                snapshot_development_runtime_for_launch(
                    _DictSubclass(case.manifest),
                    case.evidence,
                    expected_manifest_sha256=case.manifest["manifest_sha256"],
                )
            with self.assertRaises(DevelopmentRuntimeFdSnapshotError):
                snapshot_development_runtime_for_launch(
                    case.manifest,
                    case.evidence,
                    expected_manifest_sha256=_StrSubclass(
                        case.manifest["manifest_sha256"]
                    ),
                )

            snapshot = case.snapshot()
            path = snapshot.regular_slots[0].destination_path
            with self.assertRaises(DevelopmentRuntimeFdSnapshotError):
                snapshot.duplicate_regular_fd(_StrSubclass(path))
            snapshot.close()
            for changes in (
                {"launch_eligible": True},
                {"directory_count": snapshot.directory_count + 1},
                {"source_projection_sha256": "0" * 64},
                {"source_evidence_sha256": "0" * 64},
                {"snapshot_index_sha256": "0" * 64},
                {"snapshot_sha256": "0" * 64},
            ):
                with self.subTest(changes=changes):
                    with self.assertRaises(DevelopmentRuntimeFdSnapshotError):
                        replace(snapshot, **changes)
            self.assertFalse(verify_development_runtime_fd_snapshot_structure(object()))

            slot = snapshot.regular_slots[0]
            with self.assertRaises(DevelopmentRuntimeFdSnapshotError):
                DevelopmentRuntimeFdSlot(
                    slot_id=_StrSubclass(slot.slot_id),
                    destination_path=slot.destination_path,
                    materialized_mode=slot.materialized_mode,
                    size=slot.size,
                    content_sha256=slot.content_sha256,
                    required_content_seals=slot.required_content_seals,
                )
            with self.assertRaises(DevelopmentRuntimeFdSnapshotError):
                DevelopmentRuntimeFdSlot(
                    slot_id=slot.slot_id,
                    destination_path=slot.destination_path,
                    materialized_mode=slot.materialized_mode,
                    size=True,
                    content_sha256=slot.content_sha256,
                    required_content_seals=slot.required_content_seals,
                )

    def test_missing_platform_primitives_and_fd_budget_fail_before_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            for owner, attribute in (
                (fd_snapshot.os, "memfd_create"),
                (fd_snapshot.fcntl, "F_SEAL_WRITE"),
            ):
                with self.subTest(attribute=attribute):
                    with (
                        mock.patch.object(owner, attribute, None),
                        mock.patch.object(
                            fd_snapshot,
                            "_capture_regular_memfd",
                            side_effect=AssertionError("capture attempted"),
                        ),
                    ):
                        with self.assertRaises(DevelopmentRuntimeFdSnapshotError):
                            case.snapshot()

            with mock.patch.object(
                fd_snapshot.resource,
                "getrlimit",
                return_value=(1, 1),
            ):
                with self.assertRaisesRegex(
                    DevelopmentRuntimeFdSnapshotError,
                    "descriptor budget",
                ):
                    fd_snapshot._preflight_descriptor_budget(1)


if __name__ == "__main__":
    unittest.main()
