from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
from hashlib import sha256
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from cbds.development_runtime_bundle import (
    DevelopmentRuntimeExecutable,
    build_development_runtime_bundle_manifest,
)
import cbds.development_runtime_materializer as materializer
from cbds.development_runtime_materializer import (
    DevelopmentRuntimeMaterializationError,
    materialize_development_runtime_bundle,
    verify_development_runtime_materialization_binding,
    verify_development_runtime_materialization_evidence_structure,
)


def _minimal_static_elf() -> bytes:
    """Return a parser-valid ELF64 with one PT_LOAD and no dependencies."""

    identity = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\0" * 8
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # ET_EXEC
        62,  # EM_X86_64
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
        1,  # PT_LOAD
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


def materialize(
    case: _RuntimeCase,
    destination: Path,
    *,
    manifest: object | None = None,
):
    return materialize_development_runtime_bundle(
        case.manifest if manifest is None else manifest,
        destination,
        expected_manifest_sha256=case.manifest["manifest_sha256"],
    )


class DevelopmentRuntimeMaterializerTests(unittest.TestCase):
    def test_materializes_exact_projection_and_returns_non_authorizing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            destination = Path(temporary) / "runtime-root"

            evidence = materialize(case, destination)

            copied_regular = destination / case.regular.relative_to("/")
            copied_alias = destination / case.alias.relative_to("/")
            self.assertEqual(copied_regular.read_bytes(), case.payload)
            self.assertEqual(stat_mode(copied_regular), 0o555)
            self.assertEqual(stat_mode(destination), 0o555)
            self.assertTrue(copied_alias.is_symlink())
            self.assertEqual(os.readlink(copied_alias), "runtime.bin")
            self.assertEqual(evidence.source_manifest_sha256, case.manifest["manifest_sha256"])
            self.assertEqual(evidence.entry_count, 2)
            self.assertEqual(evidence.regular_file_count, 1)
            self.assertEqual(evidence.symlink_count, 1)
            self.assertEqual(evidence.regular_payload_bytes, len(case.payload))
            self.assertEqual(evidence.first_scan_sha256, evidence.second_scan_sha256)
            self.assertTrue(evidence.runtime_bundle_materialized)
            self.assertFalse(evidence.same_uid_mutation_resistant)
            self.assertFalse(evidence.fd_bound_launch_handoff)
            self.assertFalse(evidence.launch_eligible)
            self.assertFalse(evidence.candidate_execution_authorized)
            self.assertFalse(evidence.claim_pipeline_eligible)
            self.assertFalse(evidence.scored_evaluation_eligible)
            self.assertTrue(
                verify_development_runtime_materialization_evidence_structure(
                    evidence
                )
            )
            self.assertTrue(
                verify_development_runtime_materialization_binding(
                    evidence,
                    case.manifest,
                    expected_manifest_sha256=case.manifest["manifest_sha256"],
                )
            )
            self.assertEqual(
                evidence.to_record()["evidence_sha256"], evidence.evidence_sha256
            )
            with self.assertRaises(FrozenInstanceError):
                evidence.destination_root = "/forged"  # type: ignore[misc]

    def test_requires_a_strictly_new_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            destination = Path(temporary) / "already-there"
            destination.mkdir()
            with self.assertRaisesRegex(
                DevelopmentRuntimeMaterializationError,
                "already exists",
            ):
                materialize(case, destination)

    def test_requires_a_trusted_manifest_digest_before_source_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            destination = Path(temporary) / "runtime-root"
            with self.assertRaisesRegex(
                DevelopmentRuntimeMaterializationError,
                "trusted expected digest",
            ):
                materialize_development_runtime_bundle(
                    case.manifest,
                    destination,
                    expected_manifest_sha256="0" * 64,
                )
            self.assertFalse(destination.exists())

    def test_manifest_hard_bounds_apply_before_source_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            forged = dict(case.manifest)
            forged["maximum_file_bytes"] = 2**63 - 1
            destination = Path(temporary) / "runtime-root"
            with mock.patch.object(
                materializer,
                "validate_development_runtime_bundle_manifest",
            ) as replay:
                with self.assertRaisesRegex(
                    DevelopmentRuntimeMaterializationError,
                    "hard bound",
                ):
                    materialize_development_runtime_bundle(
                        forged,
                        destination,
                        expected_manifest_sha256=case.manifest["manifest_sha256"],
                    )
            replay.assert_not_called()
            self.assertFalse(destination.exists())

    def test_non_utf8_destination_is_rejected_before_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            destination = Path(temporary) / "runtime-\udc80"
            with self.assertRaisesRegex(
                DevelopmentRuntimeMaterializationError,
                "strict UTF-8",
            ):
                materialize(case, destination)
            self.assertFalse(os.path.lexists(destination))
            double_slash = "//" + str(
                Path(temporary) / "double-slash-root"
            ).lstrip("/")
            with self.assertRaisesRegex(
                DevelopmentRuntimeMaterializationError,
                "normalized non-root absolute path",
            ):
                materialize_development_runtime_bundle(
                    case.manifest,
                    double_slash,
                    expected_manifest_sha256=case.manifest["manifest_sha256"],
                )
            self.assertFalse(
                os.path.lexists(Path(temporary) / "double-slash-root")
            )
        for value in ("//", "//tmp/runtime-root"):
            with self.subTest(value=value):
                with self.assertRaises(DevelopmentRuntimeMaterializationError):
                    materializer._absolute_destination_root(value)
        with self.assertRaisesRegex(
            DevelopmentRuntimeMaterializationError,
            "strict UTF-8",
        ):
            materializer._absolute_runtime_path("/runtime-\udc80")
        with self.assertRaisesRegex(
            DevelopmentRuntimeMaterializationError,
            "strict UTF-8",
        ):
            materializer._validate_symlink_target("/runtime", "target-\udc80")

    def test_rejects_a_symbolic_destination_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case = _RuntimeCase(root)
            real_parent = root / "real-parent"
            real_parent.mkdir()
            alias_parent = root / "alias-parent"
            alias_parent.symlink_to(real_parent)
            with self.assertRaises(DevelopmentRuntimeMaterializationError):
                materialize(case, alias_parent / "runtime-root")
            self.assertFalse((real_parent / "runtime-root").exists())

    def test_rejects_subclassed_nested_manifest_values_before_creation(self) -> None:
        class ActiveList(list[object]):
            pass

        class ActiveDictionary(dict[str, object]):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            forged = dict(case.manifest)
            forged["entries"] = ActiveList(case.manifest["entries"])  # type: ignore[arg-type]
            destination = Path(temporary) / "runtime-root"
            with self.assertRaisesRegex(
                DevelopmentRuntimeMaterializationError,
                "shell array",
            ):
                materialize(case, destination, manifest=forged)
            self.assertFalse(destination.exists())
            with self.assertRaisesRegex(
                DevelopmentRuntimeMaterializationError,
                "exact dictionary",
            ):
                materialize(
                    case,
                    destination,
                    manifest=ActiveDictionary(case.manifest),
                )

            with self.assertRaisesRegex(
                DevelopmentRuntimeMaterializationError,
                "top-level shell",
            ):
                materialize_development_runtime_bundle(
                    {"bad": "\udc80"},
                    destination,
                    expected_manifest_sha256="0" * 64,
                )
            self.assertFalse(destination.exists())

            with self.assertRaisesRegex(
                DevelopmentRuntimeMaterializationError,
                "top-level shell",
            ):
                materialize_development_runtime_bundle(
                    {"\udc80": "bad-key"},
                    destination,
                    expected_manifest_sha256="0" * 64,
                )
            self.assertFalse(destination.exists())
            with self.assertRaisesRegex(
                DevelopmentRuntimeMaterializationError,
                "strict UTF-8",
            ):
                materializer._strict_plain_json_copy({"bad": "\udc80"})
            with self.assertRaisesRegex(
                DevelopmentRuntimeMaterializationError,
                "strict UTF-8",
            ):
                materializer._strict_plain_json_copy({"\udc80": "bad-key"})

    def test_manifest_shell_and_nested_list_bounds_precede_deep_clone(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            destination = Path(temporary) / "runtime-root"
            extra = dict(case.manifest)
            extra["unreviewed"] = [object()] * 1000
            wrong_schema = dict(case.manifest)
            wrong_schema["schema_version"] = "unreviewed"
            oversized = dict(case.manifest)
            resolution = dict(case.manifest["library_resolution"])
            resolution["resolutions"] = [
                {}
            ] * (materializer.MAXIMUM_LIBRARY_LOOKUP_CANDIDATES + 1)
            oversized["library_resolution"] = resolution

            for forged, message in (
                (extra, "top-level shell"),
                (wrong_schema, "schema shell"),
                (oversized, "resolution shell"),
            ):
                with self.subTest(message=message):
                    with mock.patch.object(
                        materializer,
                        "_strict_plain_json_copy",
                    ) as deep_copy:
                        with self.assertRaisesRegex(
                            DevelopmentRuntimeMaterializationError,
                            message,
                        ):
                            materialize_development_runtime_bundle(
                                forged,
                                destination,
                                expected_manifest_sha256=case.manifest[
                                    "manifest_sha256"
                                ],
                            )
                    deep_copy.assert_not_called()
                    self.assertFalse(destination.exists())

    def test_generic_json_clone_has_tight_depth_and_string_bounds(self) -> None:
        nested: object = "leaf"
        for _index in range(materializer.MAXIMUM_STRICT_JSON_DEPTH + 1):
            nested = [nested]
        with self.assertRaisesRegex(
            DevelopmentRuntimeMaterializationError,
            "strict JSON bounds",
        ):
            materializer._strict_plain_json_copy({"nested": nested})
        with self.assertRaisesRegex(
            DevelopmentRuntimeMaterializationError,
            "string exceeds",
        ):
            materializer._strict_plain_json_copy(
                {
                    "oversized": "x"
                    * (materializer.MAXIMUM_STRICT_JSON_STRING_BYTES + 1)
                }
            )

    def test_rejects_a_source_changed_before_materialization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            case.regular.chmod(0o755)
            with self.assertRaisesRegex(
                DevelopmentRuntimeMaterializationError,
                "pre-materialization replay",
            ):
                materialize(case, Path(temporary) / "runtime-root")

    def test_post_copy_source_replay_detects_a_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            original = materializer._publish_regular_from_source

            def publish_then_change(root_descriptor: int, expected: object) -> None:
                original(root_descriptor, expected)  # type: ignore[arg-type]
                case.regular.chmod(0o755)

            with mock.patch.object(
                materializer,
                "_publish_regular_from_source",
                side_effect=publish_then_change,
            ):
                with self.assertRaisesRegex(
                    DevelopmentRuntimeMaterializationError,
                    "post-materialization replay",
                ):
                    materialize(case, Path(temporary) / "runtime-root")

    def test_final_double_scan_detects_destination_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            destination = Path(temporary) / "runtime-root"
            original = materializer._scan_destination_once
            calls = 0

            def scan_then_mutate(*args: object, **kwargs: object) -> object:
                nonlocal calls
                result = original(*args, **kwargs)  # type: ignore[arg-type]
                if calls == 0:
                    (destination / "intruder").write_bytes(b"race")
                calls += 1
                return result

            with mock.patch.object(
                materializer,
                "_scan_destination_once",
                side_effect=scan_then_mutate,
            ):
                with self.assertRaises(DevelopmentRuntimeMaterializationError):
                    materialize(case, destination)

    def test_live_binding_rejects_post_materialization_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            destination = Path(temporary) / "runtime-root"
            evidence = materialize(case, destination)
            self.assertTrue(
                verify_development_runtime_materialization_binding(
                    evidence,
                    case.manifest,
                    expected_manifest_sha256=case.manifest["manifest_sha256"],
                )
            )
            # Same-UID ownership means mode 0555 is not a security boundary:
            # the owner can chmod and mutate it.  The explicit flag stays false
            # and point-in-time rebinding must detect the resulting change.
            destination.chmod(0o755)
            (destination / "intruder").write_bytes(b"changed")
            self.assertTrue(
                verify_development_runtime_materialization_evidence_structure(
                    evidence
                )
            )
            self.assertFalse(
                verify_development_runtime_materialization_binding(
                    evidence,
                    case.manifest,
                    expected_manifest_sha256=case.manifest["manifest_sha256"],
                )
            )

    def test_evidence_revalidation_rejects_forged_flags_and_nested_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            evidence = materialize(case, Path(temporary) / "runtime-root")
            object.__setattr__(evidence, "launch_eligible", True)
            self.assertFalse(
                verify_development_runtime_materialization_evidence_structure(
                    evidence
                )
            )
            with self.assertRaises(DevelopmentRuntimeMaterializationError):
                evidence.to_record()

            other = materialize(case, Path(temporary) / "second-root")
            object.__setattr__(other, "entries", list(other.entries))
            self.assertFalse(
                verify_development_runtime_materialization_evidence_structure(other)
            )

            deleted = materialize(case, Path(temporary) / "third-root")
            object.__delattr__(deleted, "entries")
            self.assertFalse(
                verify_development_runtime_materialization_evidence_structure(
                    deleted
                )
            )

    def test_structural_evidence_requires_nonempty_rooted_projection(self) -> None:
        with self.assertRaises(DevelopmentRuntimeMaterializationError):
            materializer._construct_evidence(
                source_manifest_sha256="0" * 64,
                destination_root="/definitely-not-materialized",
                directories=(),
                entries=(),
                first_scan_sha256="1" * 64,
                second_scan_sha256="1" * 64,
            )

    def test_structural_evidence_rejects_unused_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _RuntimeCase(Path(temporary))
            evidence = materialize(case, Path(temporary) / "runtime-root")
            unused = materializer.DevelopmentRuntimeMaterializedDirectory(
                destination_path="/unused",
                mode=materializer.MATERIALIZED_DIRECTORY_MODE,
                link_count=2,
            )
            directories = tuple(
                sorted(
                    (*evidence.directories, unused),
                    key=lambda item: item.destination_path.encode("utf-8"),
                )
            )
            with self.assertRaisesRegex(
                DevelopmentRuntimeMaterializationError,
                "unused directory",
            ):
                materializer._construct_evidence(
                    source_manifest_sha256=evidence.source_manifest_sha256,
                    destination_root=evidence.destination_root,
                    directories=directories,
                    entries=evidence.entries,
                    first_scan_sha256=evidence.first_scan_sha256,
                    second_scan_sha256=evidence.second_scan_sha256,
                )

    def test_scan_rejects_a_child_replaced_after_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "runtime-root"
            root.mkdir()
            child = root / "child"
            child.mkdir()
            (child / "leaf").symlink_to("missing")
            child.chmod(0o555)
            root.chmod(0o555)
            metadata = os.stat(child / "leaf", follow_symlinks=False)
            expected = materializer._ExpectedEntry(
                source_path="/child/leaf",
                destination_path="/child/leaf",
                kind="symlink",
                mode=metadata.st_mode & 0o7777,
                uid=metadata.st_uid,
                gid=metadata.st_gid,
                size=metadata.st_size,
                sha256=None,
                target="missing",
            )
            root_descriptor = os.open(root, materializer._directory_flags())
            original_open_relative = materializer._static._open_relative_directory
            replaced = False

            def replace_then_open(
                descriptor: int,
                relative: object,
            ) -> int:
                nonlocal replaced
                if str(relative) == "child" and not replaced:
                    replaced = True
                    root.chmod(0o755)
                    child.rename(root / "displaced-child")
                    child.mkdir()
                    (child / "leaf").symlink_to("missing")
                    child.chmod(0o555)
                    root.chmod(0o555)
                return original_open_relative(descriptor, relative)  # type: ignore[arg-type]

            try:
                with mock.patch.object(
                    materializer._static,
                    "_open_relative_directory",
                    side_effect=replace_then_open,
                ):
                    with self.assertRaisesRegex(
                        DevelopmentRuntimeMaterializationError,
                        "changed before traversal",
                    ):
                        materializer._scan_destination_once(
                            root_descriptor,
                            (expected,),
                            ("/", "/child"),
                        )
            finally:
                os.close(root_descriptor)

    def test_scan_descriptor_use_is_bounded_by_depth_not_width(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime-root"
            root.mkdir()
            expected_entries = []
            expected_directories = ["/"]
            for index in range(128):
                relative_directory = f"d{index:03d}"
                directory = root / relative_directory
                directory.mkdir()
                leaf = directory / "leaf"
                leaf.symlink_to("missing")
                directory.chmod(0o555)
                metadata = os.stat(leaf, follow_symlinks=False)
                destination_path = f"/{relative_directory}/leaf"
                expected_directories.append(f"/{relative_directory}")
                expected_entries.append(
                    materializer._ExpectedEntry(
                        source_path=destination_path,
                        destination_path=destination_path,
                        kind="symlink",
                        mode=metadata.st_mode & 0o7777,
                        uid=metadata.st_uid,
                        gid=metadata.st_gid,
                        size=metadata.st_size,
                        sha256=None,
                        target="missing",
                    )
                )
            root.chmod(0o555)
            root_descriptor = os.open(root, materializer._directory_flags())
            real_open = os.open
            real_close = os.close
            tracked_directories: set[int] = set()
            maximum_open_directories = 0

            def tracked_open(*args: object, **kwargs: object) -> int:
                nonlocal maximum_open_directories
                descriptor = real_open(*args, **kwargs)  # type: ignore[arg-type]
                if materializer.stat.S_ISDIR(os.fstat(descriptor).st_mode):
                    tracked_directories.add(descriptor)
                    maximum_open_directories = max(
                        maximum_open_directories,
                        len(tracked_directories),
                    )
                return descriptor

            def tracked_close(descriptor: int) -> None:
                tracked_directories.discard(descriptor)
                real_close(descriptor)

            try:
                with (
                    mock.patch.object(
                        materializer.os,
                        "open",
                        side_effect=tracked_open,
                    ),
                    mock.patch.object(
                        materializer.os,
                        "close",
                        side_effect=tracked_close,
                    ),
                ):
                    _, directories, entries = materializer._scan_destination_once(
                        root_descriptor,
                        tuple(expected_entries),
                        tuple(expected_directories),
                    )
                self.assertEqual(len(directories), 129)
                self.assertEqual(len(entries), 128)
                self.assertLessEqual(maximum_open_directories, 2)
                self.assertFalse(tracked_directories)
            finally:
                real_close(root_descriptor)

    def test_mode_normalization_strips_all_write_and_privilege_bits(self) -> None:
        self.assertEqual(materializer._materialized_regular_mode(0o755), 0o555)
        self.assertEqual(materializer._materialized_regular_mode(0o644), 0o444)
        self.assertEqual(materializer._materialized_regular_mode(0o6755), 0o555)

    def test_module_has_no_process_launch_calls(self) -> None:
        source = Path(materializer.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        forbidden_names = {
            "execv",
            "execve",
            "execvp",
            "execvpe",
            "fork",
            "posix_spawn",
            "posix_spawnp",
            "popen",
            "run",
            "system",
        }
        calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    calls.append(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    calls.append(node.func.attr)
        self.assertFalse(forbidden_names & set(calls))
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertFalse({"subprocess", "multiprocessing"} & imported)


def stat_mode(path: Path) -> int:
    return os.stat(path, follow_symlinks=False).st_mode & 0o7777


if __name__ == "__main__":
    unittest.main()
