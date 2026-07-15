from __future__ import annotations

import copy
from hashlib import sha256
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.development_runtime_bundle as runtime_bundle  # noqa: E402
from cbds.development_runtime_bundle import (  # noqa: E402
    MAXIMUM_ALLOWED_SOURCE_ROOTS,
    DevelopmentRuntimeBundleError,
    DevelopmentRuntimeExecutable,
    build_development_runtime_bundle_manifest,
    compute_development_runtime_bundle_sha256,
    validate_development_runtime_bundle_manifest,
    verify_development_runtime_bundle_manifest,
    verify_development_runtime_bundle_sha256,
)


def synthetic_elf(
    *,
    object_type: int,
    interpreter: str | None = None,
    needed: tuple[str, ...] = (),
    include_runpath: bool = False,
) -> bytes:
    """Build a small parseable ELF fixture; it is never executed."""

    phnum = 1 + (interpreter is not None) + bool(needed or include_runpath)
    total_size = 2048
    payload = bytearray(total_size)
    payload[:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        payload,
        16,
        object_type,
        62,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        phnum,
        0,
        0,
        0,
    )
    program_headers: list[tuple[int, int, int, int, int, int, int, int]] = [
        (1, 5, 0, 0, 0, total_size, total_size, 4096)
    ]
    if interpreter is not None:
        encoded = interpreter.encode("utf-8") + b"\x00"
        payload[512 : 512 + len(encoded)] = encoded
        program_headers.append((3, 4, 512, 512, 512, len(encoded), len(encoded), 1))
    if needed or include_runpath:
        strings = bytearray(b"\x00")
        offsets: dict[str, int] = {}
        for name in needed:
            offsets[name] = len(strings)
            strings.extend(name.encode("utf-8") + b"\x00")
        if include_runpath:
            offsets["runpath"] = len(strings)
            strings.extend(b"/unsupported\x00")
        payload[1024 : 1024 + len(strings)] = strings
        dynamic: list[tuple[int, int]] = [
            *((1, offsets[name]) for name in needed),
            (5, 1024),
            (10, len(strings)),
        ]
        if include_runpath:
            dynamic.append((29, offsets["runpath"]))
        dynamic.append((0, 0))
        for index, item in enumerate(dynamic):
            struct.pack_into("<qQ", payload, 768 + index * 16, *item)
        dynamic_size = len(dynamic) * 16
        program_headers.append(
            (2, 4, 768, 768, 768, dynamic_size, dynamic_size, 8)
        )
    for index, values in enumerate(program_headers):
        struct.pack_into("<IIQQQQQQ", payload, 64 + index * 56, *values)
    return bytes(payload)


class RuntimeTree:
    def __init__(self, parent: Path, *, runpath: bool = False) -> None:
        self.root = parent / "runtime"
        self.bin = self.root / "bin"
        self.lib = self.root / "lib"
        self.bin.mkdir(parents=True)
        self.lib.mkdir()
        self.interpreter = self.lib / "ld-real"
        self.library = self.lib / "libanswer-real.so"
        self.app = self.bin / "app-real"
        self.interpreter.write_bytes(synthetic_elf(object_type=3))
        self.library.write_bytes(synthetic_elf(object_type=3))
        self.app.write_bytes(
            synthetic_elf(
                object_type=2,
                interpreter=str(self.lib / "ld-test"),
                needed=("libanswer.so",),
                include_runpath=runpath,
            )
        )
        self.tool = self.bin / "tool"
        self.tool.symlink_to("app-real")
        (self.lib / "ld-test").symlink_to("ld-real")
        (self.lib / "libanswer.so").symlink_to("libanswer-real.so")
        os.chmod(self.app, 0o555)
        os.chmod(self.interpreter, 0o555)
        os.chmod(self.library, 0o444)

    @property
    def expected_sha256(self) -> str:
        return sha256(self.app.read_bytes()).hexdigest()

    def executable(
        self,
        *,
        name: str = "tool",
        path: Path | None = None,
    ) -> DevelopmentRuntimeExecutable:
        return DevelopmentRuntimeExecutable(
            name=name,
            source_path=str(self.tool if path is None else path),
            expected_sha256=self.expected_sha256,
        )

    def build(self) -> dict[str, object]:
        return build_development_runtime_bundle_manifest(
            [self.executable()],
            allowed_source_roots=[str(self.root)],
            library_search_directories=[str(self.lib)],
        )


class ExecutableRecordTests(unittest.TestCase):
    def test_record_rejects_malformed_names_paths_and_digests(self) -> None:
        cases = (
            {"name": "Bad Name", "source_path": "/a", "expected_sha256": "0" * 64},
            {"name": "ok", "source_path": "relative", "expected_sha256": "0" * 64},
            {"name": "ok", "source_path": "/a/../b", "expected_sha256": "0" * 64},
            {"name": "ok", "source_path": "/a", "expected_sha256": "A" * 64},
        )
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(ValueError):
                    DevelopmentRuntimeExecutable(**case)


class ManifestBuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.tree = RuntimeTree(Path(self.temporary.name))

    def test_build_resolves_symlink_interpreter_and_needed_closure(self) -> None:
        manifest = self.tree.build()
        entries = manifest["entries"]
        self.assertIsInstance(entries, list)
        by_path = {entry["destination_path"]: entry for entry in entries}
        expected_paths = {
            str(self.tree.tool),
            str(self.tree.app),
            str(self.tree.lib / "ld-test"),
            str(self.tree.interpreter),
            str(self.tree.lib / "libanswer.so"),
            str(self.tree.library),
        }
        self.assertEqual(set(by_path), expected_paths)
        self.assertEqual(by_path[str(self.tree.tool)]["kind"], "symlink")
        self.assertEqual(by_path[str(self.tree.tool)]["target"], "app-real")
        self.assertEqual(
            by_path[str(self.tree.app)]["sha256"], self.tree.expected_sha256
        )
        self.assertEqual(
            by_path[str(self.tree.app)]["elf"]["pt_interp"],
            str(self.tree.lib / "ld-test"),
        )
        self.assertEqual(
            by_path[str(self.tree.app)]["elf"]["dt_needed"],
            ["libanswer.so"],
        )
        self.assertIn(
            "elf_interpreter", by_path[str(self.tree.interpreter)]["roles"]
        )
        self.assertIn("shared_library", by_path[str(self.tree.library)]["roles"])
        self.assertEqual(manifest["closure"]["entry_count"], 6)
        self.assertEqual(manifest["closure"]["regular_payload_bytes"], 6144)
        self.assertGreaterEqual(
            manifest["maximum_total_regular_payload_bytes"],
            manifest["closure"]["regular_payload_bytes"],
        )
        self.assertGreaterEqual(manifest["maximum_manifest_entries"], 6)
        self.assertTrue(manifest["closure"]["elf_pt_interp_dt_needed_verified"])
        self.assertFalse(
            manifest["closure"]["runtime_data_and_dlopen_closure_verified"]
        )
        self.assertTrue(verify_development_runtime_bundle_sha256(manifest))

        resolution = manifest["library_resolution"]
        self.assertTrue(
            resolution["search_precedence_and_negative_lookups_verified"]
        )
        self.assertEqual(resolution["resolution_count"], 1)
        self.assertEqual(resolution["negative_lookup_count"], 0)
        self.assertEqual(
            resolution["resolutions"][0]["searches"],
            [
                {
                    "search_directory_index": 0,
                    "directory": str(self.tree.lib),
                    "candidate_path": str(self.tree.lib / "libanswer.so"),
                    "outcome": "selected",
                }
            ],
        )

    def test_manifest_never_authorizes_execution_or_claims(self) -> None:
        manifest = self.tree.build()
        for field in (
            "runtime_bundle_materialized",
            "launch_eligible",
            "candidate_execution_authorized",
            "claim_pipeline_eligible",
            "scored_evaluation_eligible",
        ):
            self.assertIs(manifest[field], False)

    def test_build_is_canonical_and_strict_validation_replays_sources(self) -> None:
        first = self.tree.build()
        second = self.tree.build()
        self.assertEqual(first, second)
        validate_development_runtime_bundle_manifest(first)
        self.assertTrue(verify_development_runtime_bundle_manifest(first))

    def test_digest_mismatch_and_writable_or_privileged_source_fail_closed(self) -> None:
        wrong = DevelopmentRuntimeExecutable(
            name="tool",
            source_path=str(self.tree.tool),
            expected_sha256="0" * 64,
        )
        with self.assertRaisesRegex(DevelopmentRuntimeBundleError, "digest mismatch"):
            build_development_runtime_bundle_manifest(
                [wrong],
                allowed_source_roots=[str(self.tree.root)],
                library_search_directories=[str(self.tree.lib)],
            )

        os.chmod(self.tree.app, 0o755)
        with self.assertRaisesRegex(DevelopmentRuntimeBundleError, "writable"):
            self.tree.build()
        os.chmod(self.tree.app, 0o4555)
        with self.assertRaisesRegex(DevelopmentRuntimeBundleError, "setuid"):
            self.tree.build()

    def test_acl_capability_and_effective_write_ambiguity_fail_closed(self) -> None:
        for attribute in ("system.posix_acl_access", "security.capability"):
            with self.subTest(attribute=attribute):
                with mock.patch.object(
                    runtime_bundle.os,
                    "listxattr",
                    return_value=[attribute],
                ):
                    with self.assertRaisesRegex(
                        DevelopmentRuntimeBundleError,
                        "ambiguous ACL or capability",
                    ):
                        self.tree.build()

        with (
            mock.patch.object(runtime_bundle.os, "listxattr", return_value=[]),
            mock.patch.object(runtime_bundle.os, "access", return_value=True),
        ):
            with self.assertRaisesRegex(
                DevelopmentRuntimeBundleError,
                "effective write access",
            ):
                self.tree.build()

        with mock.patch.object(
            runtime_bundle.os,
            "listxattr",
            side_effect=OSError("unsupported"),
        ):
            with self.assertRaisesRegex(
                DevelopmentRuntimeBundleError,
                "cannot establish runtime source access metadata",
            ):
                self.tree.build()

    def test_interpreter_must_itself_be_nonwritable_and_executable(self) -> None:
        os.chmod(self.tree.interpreter, 0o444)
        with self.assertRaisesRegex(DevelopmentRuntimeBundleError, "interpreter lacks"):
            self.tree.build()

    def test_outside_broken_nonregular_and_duplicate_destinations_fail_closed(self) -> None:
        outside = Path(self.temporary.name) / "outside"
        outside.write_bytes(synthetic_elf(object_type=2))
        os.chmod(outside, 0o555)
        self.tree.tool.unlink()
        self.tree.tool.symlink_to(outside)
        with self.assertRaisesRegex(DevelopmentRuntimeBundleError, "outside allowed"):
            self.tree.build()

        self.tree.tool.unlink()
        self.tree.tool.symlink_to("missing")
        with self.assertRaisesRegex(DevelopmentRuntimeBundleError, "missing"):
            self.tree.build()

        self.tree.tool.unlink()
        os.mkfifo(self.tree.tool, 0o444)
        with self.assertRaisesRegex(DevelopmentRuntimeBundleError, "not a regular"):
            self.tree.build()

        self.tree.tool.unlink()
        self.tree.tool.symlink_to("app-real")
        alias = self.tree.bin / "tool-alias"
        alias.symlink_to("app-real")
        with self.assertRaisesRegex(DevelopmentRuntimeBundleError, "resolve uniquely"):
            build_development_runtime_bundle_manifest(
                [self.tree.executable(), self.tree.executable(name="alias", path=alias)],
                allowed_source_roots=[str(self.tree.root)],
                library_search_directories=[str(self.tree.lib)],
            )

    def test_allowed_root_cannot_hide_an_outside_tree_behind_a_symlink(self) -> None:
        alias = Path(self.temporary.name) / "runtime-alias"
        alias.symlink_to(self.tree.root, target_is_directory=True)
        aliased_tool = alias / "bin" / "tool"
        executable = DevelopmentRuntimeExecutable(
            name="aliased",
            source_path=str(aliased_tool),
            expected_sha256=self.tree.expected_sha256,
        )
        with self.assertRaisesRegex(
            DevelopmentRuntimeBundleError,
            "outside allowed",
        ):
            build_development_runtime_bundle_manifest(
                [executable],
                allowed_source_roots=[str(alias)],
                library_search_directories=[str(alias / "lib")],
            )

    def test_declared_symlink_root_alias_into_another_declared_root_is_recorded(self) -> None:
        alias = Path(self.temporary.name) / "runtime-alias"
        alias.symlink_to(self.tree.root, target_is_directory=True)
        executable = DevelopmentRuntimeExecutable(
            name="aliased",
            source_path=str(alias / "bin" / "tool"),
            expected_sha256=self.tree.expected_sha256,
        )
        manifest = build_development_runtime_bundle_manifest(
            [executable],
            allowed_source_roots=[str(alias), str(self.tree.root)],
            library_search_directories=[str(alias / "lib")],
        )
        by_path = {
            entry["destination_path"]: entry for entry in manifest["entries"]
        }
        self.assertEqual(by_path[str(alias)]["kind"], "symlink")
        self.assertEqual(by_path[str(alias)]["target"], str(self.tree.root))
        resolution = manifest["library_resolution"]["resolutions"][0]
        self.assertEqual(
            resolution["selected_source_path"],
            str(alias / "lib" / "libanswer.so"),
        )
        self.assertTrue(verify_development_runtime_bundle_manifest(manifest))

    def test_missing_dependency_and_runpath_are_rejected_not_approximated(self) -> None:
        (self.tree.lib / "libanswer.so").unlink()
        with self.assertRaisesRegex(DevelopmentRuntimeBundleError, "unresolved DT_NEEDED"):
            self.tree.build()

        other = RuntimeTree(Path(self.temporary.name) / "other", runpath=True)
        with self.assertRaisesRegex(DevelopmentRuntimeBundleError, "RPATH/RUNPATH"):
            other.build()

    def test_non_elf_closure_member_and_file_limit_fail_closed(self) -> None:
        os.chmod(self.tree.library, 0o644)
        self.tree.library.write_bytes(b"not elf")
        os.chmod(self.tree.library, 0o444)
        with self.assertRaisesRegex(DevelopmentRuntimeBundleError, "not ELF"):
            self.tree.build()

        with self.assertRaisesRegex(DevelopmentRuntimeBundleError, "maximum_file_bytes"):
            build_development_runtime_bundle_manifest(
                [self.tree.executable()],
                allowed_source_roots=[str(self.tree.root)],
                library_search_directories=[str(self.tree.lib)],
                maximum_file_bytes=128,
            )

    def test_library_search_precedence_and_negative_lookup_are_replayed(self) -> None:
        earlier = self.tree.root / "earlier-lib"
        earlier.mkdir()
        manifest = build_development_runtime_bundle_manifest(
            [self.tree.executable()],
            allowed_source_roots=[str(self.tree.root)],
            library_search_directories=[str(earlier), str(self.tree.lib)],
        )
        resolution = manifest["library_resolution"]
        self.assertEqual(resolution["negative_lookup_count"], 1)
        self.assertEqual(
            [
                search["outcome"]
                for search in resolution["resolutions"][0]["searches"]
            ],
            ["missing", "selected"],
        )
        self.assertTrue(verify_development_runtime_bundle_manifest(manifest))

        (earlier / "libanswer.so").symlink_to("../lib/libanswer.so")
        self.assertTrue(verify_development_runtime_bundle_sha256(manifest))
        self.assertFalse(verify_development_runtime_bundle_manifest(manifest))

    def test_unbounded_record_and_string_iterables_stop_at_hard_limits(self) -> None:
        executable_yields = 0

        def endless_executables():
            nonlocal executable_yields
            index = 0
            while True:
                executable_yields += 1
                yield DevelopmentRuntimeExecutable(
                    name=f"tool-{index}",
                    source_path=str(self.tree.bin / f"missing-{index}"),
                    expected_sha256="0" * 64,
                )
                index += 1

        with self.assertRaisesRegex(
            DevelopmentRuntimeBundleError,
            "exceeds maximum_manifest_entries",
        ):
            build_development_runtime_bundle_manifest(
                endless_executables(),
                allowed_source_roots=[str(self.tree.root)],
                library_search_directories=[str(self.tree.lib)],
                maximum_manifest_entries=3,
            )
        self.assertEqual(executable_yields, 4)

        root_yields = 0

        def endless_roots():
            nonlocal root_yields
            index = 0
            while True:
                root_yields += 1
                yield f"/bounded-runtime-root-{index}"
                index += 1

        with self.assertRaisesRegex(
            DevelopmentRuntimeBundleError,
            "allowed_source_roots exceeds its maximum count",
        ):
            build_development_runtime_bundle_manifest(
                [self.tree.executable()],
                allowed_source_roots=endless_roots(),
                library_search_directories=[str(self.tree.lib)],
            )
        self.assertEqual(root_yields, MAXIMUM_ALLOWED_SOURCE_ROOTS + 1)

    def test_entry_and_aggregate_payload_caps_fail_closed(self) -> None:
        with self.assertRaisesRegex(DevelopmentRuntimeBundleError, "entry limit"):
            build_development_runtime_bundle_manifest(
                [self.tree.executable()],
                allowed_source_roots=[str(self.tree.root)],
                library_search_directories=[str(self.tree.lib)],
                maximum_manifest_entries=5,
            )
        with self.assertRaisesRegex(
            DevelopmentRuntimeBundleError,
            "maximum_total_regular_payload_bytes",
        ):
            build_development_runtime_bundle_manifest(
                [self.tree.executable()],
                allowed_source_roots=[str(self.tree.root)],
                library_search_directories=[str(self.tree.lib)],
                maximum_total_regular_payload_bytes=6143,
            )

    def test_pinned_directory_count_is_explicitly_bounded(self) -> None:
        with mock.patch.object(
            runtime_bundle,
            "_pinned_directory_budget",
            return_value=1,
        ):
            with self.assertRaisesRegex(
                DevelopmentRuntimeBundleError,
                "pinned-directory descriptor limit",
            ):
                self.tree.build()

    def test_ancestor_swap_cannot_redirect_pinned_traversal(self) -> None:
        held = Path(self.temporary.name) / "runtime-held"
        outside = Path(self.temporary.name) / "outside-runtime"
        outside.mkdir()
        original_open = os.open
        swapped = False

        def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal swapped
            if path == "bin" and dir_fd is not None and not swapped:
                self.tree.root.rename(held)
                self.tree.root.symlink_to(outside, target_is_directory=True)
                swapped = True
            if dir_fd is None:
                return original_open(path, flags, mode)
            return original_open(path, flags, mode, dir_fd=dir_fd)

        try:
            with mock.patch(
                "cbds.development_runtime_bundle.os.open",
                new=swapping_open,
            ):
                with self.assertRaisesRegex(
                    DevelopmentRuntimeBundleError,
                    "directory disappeared|directory changed",
                ):
                    self.tree.build()
            self.assertTrue(swapped)
        finally:
            if self.tree.root.is_symlink():
                self.tree.root.unlink()
            if held.exists():
                held.rename(self.tree.root)

    def test_final_directory_revalidation_detects_swap_after_first_pass(self) -> None:
        held = Path(self.temporary.name) / "runtime-held-after-first-check"
        outside = Path(self.temporary.name) / "outside-after-first-check"
        outside.mkdir()
        original = runtime_bundle._SourceObserver._revalidate_named_directories
        calls = 0

        def swap_after_first_check(observer):
            nonlocal calls
            calls += 1
            original(observer)
            if calls == 1:
                self.tree.root.rename(held)
                self.tree.root.symlink_to(outside, target_is_directory=True)

        try:
            with mock.patch.object(
                runtime_bundle._SourceObserver,
                "_revalidate_named_directories",
                new=swap_after_first_check,
            ):
                with self.assertRaisesRegex(
                    DevelopmentRuntimeBundleError,
                    "directory disappeared|directory changed",
                ):
                    self.tree.build()
            self.assertEqual(calls, 2)
        finally:
            if self.tree.root.is_symlink():
                self.tree.root.unlink()
            if held.exists():
                held.rename(self.tree.root)


class StrictValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.tree = RuntimeTree(Path(self.temporary.name))
        self.manifest = self.tree.build()

    @staticmethod
    def rehash(manifest: dict[str, object]) -> None:
        manifest["manifest_sha256"] = compute_development_runtime_bundle_sha256(
            manifest
        )

    def test_mutated_authorization_and_unknown_fields_are_rejected_after_rehash(self) -> None:
        authorized = copy.deepcopy(self.manifest)
        authorized["candidate_execution_authorized"] = True
        self.rehash(authorized)
        self.assertFalse(verify_development_runtime_bundle_manifest(authorized))

        extra = copy.deepcopy(self.manifest)
        extra["unreviewed"] = False
        self.rehash(extra)
        self.assertFalse(verify_development_runtime_bundle_manifest(extra))

    def test_duplicate_destination_and_forged_file_hash_are_rejected(self) -> None:
        duplicated = copy.deepcopy(self.manifest)
        duplicated["entries"].append(copy.deepcopy(duplicated["entries"][-1]))
        duplicated["closure"]["entry_count"] += 1
        duplicated["closure"]["regular_file_count"] += 1
        self.rehash(duplicated)
        with self.assertRaises(DevelopmentRuntimeBundleError):
            validate_development_runtime_bundle_manifest(duplicated)

        forged = copy.deepcopy(self.manifest)
        regular = next(entry for entry in forged["entries"] if entry["kind"] == "regular")
        regular["sha256"] = "f" * 64
        self.rehash(forged)
        self.assertFalse(verify_development_runtime_bundle_manifest(forged))

    def test_source_change_invalidates_a_previously_valid_manifest(self) -> None:
        self.assertTrue(verify_development_runtime_bundle_manifest(self.manifest))
        os.chmod(self.tree.library, 0o644)
        self.tree.library.write_bytes(synthetic_elf(object_type=3) + b"changed")
        os.chmod(self.tree.library, 0o444)
        self.assertTrue(verify_development_runtime_bundle_sha256(self.manifest))
        self.assertFalse(verify_development_runtime_bundle_manifest(self.manifest))

    def test_symlink_retarget_invalidates_manifest_even_when_final_bytes_match(self) -> None:
        replacement = self.tree.bin / "app-copy"
        replacement.write_bytes(self.tree.app.read_bytes())
        os.chmod(replacement, 0o555)
        self.tree.tool.unlink()
        self.tree.tool.symlink_to("app-copy")
        self.assertFalse(verify_development_runtime_bundle_manifest(self.manifest))

    def test_rehashed_aggregate_entry_and_lookup_tampering_fail_replay(self) -> None:
        aggregate = copy.deepcopy(self.manifest)
        aggregate["maximum_total_regular_payload_bytes"] = (
            aggregate["closure"]["regular_payload_bytes"] - 1
        )
        self.rehash(aggregate)
        self.assertFalse(verify_development_runtime_bundle_manifest(aggregate))

        entries = copy.deepcopy(self.manifest)
        entries["maximum_manifest_entries"] = len(entries["entries"]) - 1
        self.rehash(entries)
        self.assertFalse(verify_development_runtime_bundle_manifest(entries))

        lookup = copy.deepcopy(self.manifest)
        lookup["library_resolution"]["lookup_candidate_count"] += 1
        self.rehash(lookup)
        self.assertFalse(verify_development_runtime_bundle_manifest(lookup))


if __name__ == "__main__":
    unittest.main()
