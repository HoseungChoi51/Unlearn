from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.development_reviewed_bash_runtime import (  # noqa: E402
    DEVELOPMENT_REVIEWED_BASH_RUNTIME_RECORD_TYPE,
    DEVELOPMENT_REVIEWED_BASH_RUNTIME_REVIEW_SCOPE,
    DevelopmentReviewedBashRuntimeError,
    FROZEN_REVIEWED_BASH_RUNTIME_ALLOWED_SOURCE_ROOTS,
    FROZEN_REVIEWED_BASH_RUNTIME_DIRECTORY_COUNT,
    FROZEN_REVIEWED_BASH_RUNTIME_ENTRY_COUNT,
    FROZEN_REVIEWED_BASH_RUNTIME_EXECUTABLE_SPECS,
    FROZEN_REVIEWED_BASH_RUNTIME_LIBRARY_SEARCH_DIRECTORIES,
    FROZEN_REVIEWED_BASH_RUNTIME_MANIFEST_SHA256,
    FROZEN_REVIEWED_BASH_RUNTIME_PROJECTION_SHA256,
    FROZEN_REVIEWED_BASH_RUNTIME_REGULAR_FILE_COUNT,
    FROZEN_REVIEWED_BASH_RUNTIME_REGULAR_PAYLOAD_BYTES,
    FROZEN_REVIEWED_BASH_RUNTIME_SNAPSHOT_INDEX_SHA256,
    FROZEN_REVIEWED_BASH_RUNTIME_SYMLINK_COUNT,
    build_development_reviewed_bash_runtime_manifest,
    development_reviewed_bash_runtime_host_compatibility,
    materialize_development_reviewed_bash_runtime,
    validate_development_reviewed_bash_runtime_case,
    verify_development_reviewed_bash_runtime_case,
)
def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class DevelopmentReviewedBashRuntimeStaticTests(unittest.TestCase):
    def test_constants_name_only_the_fixed_reviewed_runtime(self) -> None:
        self.assertEqual(
            tuple(item[:2] for item in FROZEN_REVIEWED_BASH_RUNTIME_EXECUTABLE_SPECS),
            (
                ("bash", "/usr/bin/bash"),
                ("find", "/usr/bin/find"),
                ("sort", "/usr/bin/sort"),
                ("mkdir", "/usr/bin/mkdir"),
            ),
        )
        for _name, path, digest in FROZEN_REVIEWED_BASH_RUNTIME_EXECUTABLE_SPECS:
            self.assertTrue(path.startswith("/usr/bin/"))
            self.assertEqual(len(digest), 64)
            self.assertEqual(set(digest) - set("0123456789abcdef"), set())
        self.assertEqual(
            FROZEN_REVIEWED_BASH_RUNTIME_ALLOWED_SOURCE_ROOTS,
            ("/usr", "/lib64"),
        )
        self.assertEqual(
            FROZEN_REVIEWED_BASH_RUNTIME_LIBRARY_SEARCH_DIRECTORIES,
            ("/usr/lib/x86_64-linux-gnu",),
        )

    def test_module_contains_no_launch_or_assertion_path(self) -> None:
        source = (
            ROOT / "src/cbds/development_reviewed_bash_runtime.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "import subprocess",
            "os.system",
            "os.popen",
            "subprocess.run",
            "subprocess.Popen",
            "assert ",
        ):
            self.assertNotIn(forbidden, source)


class DevelopmentReviewedBashRuntimeLiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compatible, reason = development_reviewed_bash_runtime_host_compatibility()
        if not compatible:
            raise unittest.SkipTest(
                "pinned reviewed Bash runtime is unavailable: " + reason
            )

    def test_manifest_rebuild_has_exact_roster_search_and_closure_identity(self) -> None:
        manifest = build_development_reviewed_bash_runtime_manifest()
        self.assertEqual(
            manifest["manifest_sha256"],
            FROZEN_REVIEWED_BASH_RUNTIME_MANIFEST_SHA256,
        )
        self.assertEqual(manifest["allowed_source_roots"], ["/lib64", "/usr"])
        self.assertEqual(
            manifest["library_search_directories"],
            list(FROZEN_REVIEWED_BASH_RUNTIME_LIBRARY_SEARCH_DIRECTORIES),
        )
        explicit = {
            (item["name"], item["source_path"], item["expected_sha256"])
            for item in manifest["explicit_executables"]
        }
        self.assertEqual(explicit, set(FROZEN_REVIEWED_BASH_RUNTIME_EXECUTABLE_SPECS))
        closure = manifest["closure"]
        self.assertTrue(closure["elf_pt_interp_dt_needed_verified"])
        self.assertFalse(closure["runtime_data_and_dlopen_closure_verified"])
        self.assertEqual(closure["entry_count"], FROZEN_REVIEWED_BASH_RUNTIME_ENTRY_COUNT)
        for name in (
            "runtime_bundle_materialized",
            "launch_eligible",
            "candidate_execution_authorized",
            "claim_pipeline_eligible",
            "scored_evaluation_eligible",
        ):
            self.assertIs(manifest[name], False)

    def test_case_binds_every_layer_and_audit_record_is_answer_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_development_reviewed_bash_runtime(
                Path(temporary) / "runtime"
            ) as case:
                validate_development_reviewed_bash_runtime_case(case)
                self.assertTrue(verify_development_reviewed_bash_runtime_case(case))
                audit = case.to_audit_record()
                self.assertEqual(
                    audit["record_type"],
                    DEVELOPMENT_REVIEWED_BASH_RUNTIME_RECORD_TYPE,
                )
                self.assertEqual(
                    audit["review_scope"],
                    DEVELOPMENT_REVIEWED_BASH_RUNTIME_REVIEW_SCOPE,
                )
                self.assertEqual(
                    audit["source_manifest_sha256"],
                    FROZEN_REVIEWED_BASH_RUNTIME_MANIFEST_SHA256,
                )
                self.assertEqual(
                    audit["source_projection_sha256"],
                    FROZEN_REVIEWED_BASH_RUNTIME_PROJECTION_SHA256,
                )
                self.assertEqual(
                    audit["snapshot_index_sha256"],
                    FROZEN_REVIEWED_BASH_RUNTIME_SNAPSHOT_INDEX_SHA256,
                )
                self.assertEqual(audit["snapshot_sha256"], case.snapshot_sha256)
                for name, expected in (
                    ("directory_count", FROZEN_REVIEWED_BASH_RUNTIME_DIRECTORY_COUNT),
                    ("entry_count", FROZEN_REVIEWED_BASH_RUNTIME_ENTRY_COUNT),
                    (
                        "regular_file_count",
                        FROZEN_REVIEWED_BASH_RUNTIME_REGULAR_FILE_COUNT,
                    ),
                    ("symlink_count", FROZEN_REVIEWED_BASH_RUNTIME_SYMLINK_COUNT),
                    (
                        "regular_payload_bytes",
                        FROZEN_REVIEWED_BASH_RUNTIME_REGULAR_PAYLOAD_BYTES,
                    ),
                ):
                    self.assertEqual(audit[name], expected)
                for name in (
                    "source_manifest_rebuilt_and_verified",
                    "runtime_bundle_materialized",
                    "sealed_regular_payloads_verified",
                    "same_uid_snapshot_payload_mutation_resistant",
                ):
                    self.assertIs(audit[name], True)
                for name in (
                    "runtime_data_and_dlopen_closure_verified",
                    "externally_trusted_runtime_executables",
                    "same_uid_materialized_tree_mutation_resistant",
                    "namespace_runtime_closure_verified",
                    "fd_bound_launch_handoff",
                    "launch_eligible",
                    "candidate_execution_authorized",
                    "candidate_executed",
                    "scored_evaluation_eligible",
                    "model_selection_eligible",
                    "claim_pipeline_eligible",
                    "claim_authorized",
                ):
                    self.assertIs(audit[name], False)

                encoded = _canonical(audit)
                self.assertNotIn(b"destination_root", encoded)
                self.assertNotIn(b"content_base64", encoded)
                self.assertNotIn(b"oracle", encoded)
                self.assertNotIn(b"fixture", encoded)
                self.assertNotIn(b"program", encoded)
                self.assertNotIn(b"descriptor", encoded)
                self.assertNotIn(str(temporary).encode("utf-8"), encoded)
                self.assertNotIn("_manifest=", repr(case))
                self.assertNotIn("_snapshot=", repr(case))
                with self.assertRaises(FrozenInstanceError):
                    case.case_sha256 = "0" * 64  # type: ignore[misc]
                with self.assertRaises(DevelopmentReviewedBashRuntimeError):
                    copy.copy(case)
                with self.assertRaises(DevelopmentReviewedBashRuntimeError):
                    copy.deepcopy(case)

    def test_each_regular_payload_is_sealed_and_independently_readable(self) -> None:
        required_seals = (
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_development_reviewed_bash_runtime(
                Path(temporary) / "runtime"
            ) as case:
                self.assertEqual(
                    len(case.regular_slots),
                    FROZEN_REVIEWED_BASH_RUNTIME_REGULAR_FILE_COUNT,
                )
                for slot in case.regular_slots:
                    descriptor = case.duplicate_regular_fd(slot.destination_path)
                    try:
                        self.assertFalse(os.get_inheritable(descriptor))
                        self.assertEqual(
                            fcntl.fcntl(descriptor, fcntl.F_GET_SEALS),
                            required_seals,
                        )
                        payload = os.read(descriptor, slot.size + 1)
                        self.assertEqual(len(payload), slot.size)
                        self.assertEqual(sha256(payload).hexdigest(), slot.content_sha256)
                        with self.assertRaises(OSError):
                            os.write(descriptor, b"x")
                    finally:
                        os.close(descriptor)

                first = case.regular_slots[0]
                left = case.duplicate_regular_fd(first.destination_path)
                right = case.duplicate_regular_fd(first.destination_path)
                try:
                    self.assertEqual(os.read(left, 17), os.read(right, 17))
                    self.assertEqual(os.lseek(left, 0, os.SEEK_CUR), 17)
                    self.assertEqual(os.lseek(right, 0, os.SEEK_CUR), 17)
                    os.read(left, 11)
                    self.assertEqual(os.lseek(left, 0, os.SEEK_CUR), 28)
                    self.assertEqual(os.lseek(right, 0, os.SEEK_CUR), 17)
                finally:
                    os.close(left)
                    os.close(right)

    def test_sealed_snapshot_survives_materialized_tree_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_development_reviewed_bash_runtime(
                Path(temporary) / "runtime"
            ) as case:
                entry = next(
                    item
                    for item in case.entries
                    if item.kind == "regular"
                    and item.destination_path == "/usr/bin/bash"
                )
                target = Path(
                    case._materialization.destination_root
                ) / entry.destination_path.lstrip("/")
                target.chmod(0o755)
                target.write_bytes(b"same-uid materialized-tree mutation")

                descriptor = case.duplicate_regular_fd(entry.destination_path)
                try:
                    payload = os.read(descriptor, entry.size + 1)
                finally:
                    os.close(descriptor)
                self.assertEqual(sha256(payload).hexdigest(), entry.content_sha256)
                self.assertNotEqual(payload, target.read_bytes())
                self.assertTrue(verify_development_reviewed_bash_runtime_case(case))
                self.assertFalse(
                    case.to_audit_record()[
                        "same_uid_materialized_tree_mutation_resistant"
                    ]
                )

    def test_manifest_snapshot_and_authority_mutations_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = materialize_development_reviewed_bash_runtime(
                Path(temporary) / "runtime-manifest"
            )
            try:
                case._manifest["launch_eligible"] = True
                self.assertFalse(verify_development_reviewed_bash_runtime_case(case))
                with self.assertRaises(DevelopmentReviewedBashRuntimeError):
                    validate_development_reviewed_bash_runtime_case(case)
            finally:
                case.close()

            case = materialize_development_reviewed_bash_runtime(
                Path(temporary) / "runtime-authority"
            )
            try:
                object.__setattr__(case, "candidate_execution_authorized", True)
                self.assertFalse(verify_development_reviewed_bash_runtime_case(case))
            finally:
                case.close()

            case = materialize_development_reviewed_bash_runtime(
                Path(temporary) / "runtime-snapshot"
            )
            try:
                object.__setattr__(case._snapshot, "launch_eligible", True)
                self.assertFalse(verify_development_reviewed_bash_runtime_case(case))
            finally:
                case.close()

            self.assertFalse(verify_development_reviewed_bash_runtime_case(object()))

    def test_close_is_idempotent_and_preserves_descriptor_free_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = materialize_development_reviewed_bash_runtime(
                Path(temporary) / "runtime"
            )
            slot = case.regular_slots[0]
            caller_descriptor = case.duplicate_regular_fd(slot.destination_path)
            audit = case.to_audit_record()
            case.close()
            case.close()
            try:
                self.assertTrue(case.closed)
                self.assertTrue(verify_development_reviewed_bash_runtime_case(case))
                self.assertEqual(case.to_audit_record(), audit)
                self.assertEqual(
                    sha256(os.read(caller_descriptor, slot.size + 1)).hexdigest(),
                    slot.content_sha256,
                )
                with self.assertRaises(DevelopmentReviewedBashRuntimeError):
                    case.duplicate_regular_fd(slot.destination_path)
                with self.assertRaises(DevelopmentReviewedBashRuntimeError):
                    case.__enter__()
            finally:
                os.close(caller_descriptor)

    def test_opposite_optimization_mode_constructs_and_closes_real_case(self) -> None:
        opposite = ("-O",) if sys.flags.optimize == 0 else ()
        script = """
from pathlib import Path
from tempfile import TemporaryDirectory
from cbds.development_reviewed_bash_runtime import (
    materialize_development_reviewed_bash_runtime,
    verify_development_reviewed_bash_runtime_case,
)
with TemporaryDirectory() as temporary:
    case = materialize_development_reviewed_bash_runtime(Path(temporary) / "runtime")
    if not verify_development_reviewed_bash_runtime_case(case):
        raise SystemExit(3)
    descriptor = case.duplicate_regular_fd(case.regular_slots[0].destination_path)
    case.close()
    if not verify_development_reviewed_bash_runtime_case(case):
        raise SystemExit(4)
    import os
    os.close(descriptor)
"""
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT / "src")
        completed = subprocess.run(
            [sys.executable, *opposite, "-c", script],
            cwd=ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=completed.stdout + completed.stderr,
        )


if __name__ == "__main__":
    unittest.main()
