from __future__ import annotations

from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

SCRIPT_PATH = ROOT / "scripts" / "build_executable_eighth_tranche_catalog.py"
SCRIPT_SPEC = importlib.util.spec_from_file_location(
    "cbds_build_executable_eighth_tranche_catalog",
    SCRIPT_PATH,
)
if SCRIPT_SPEC is None or SCRIPT_SPEC.loader is None:
    raise RuntimeError("eighth-tranche report builder cannot be loaded")
REPORT_SCRIPT = importlib.util.module_from_spec(SCRIPT_SPEC)
sys.modules[SCRIPT_SPEC.name] = REPORT_SCRIPT
SCRIPT_SPEC.loader.exec_module(REPORT_SCRIPT)

from cbds.executable_fixture_eighth_catalog import (  # noqa: E402
    build_eighth_tranche_fixture_catalog,
)


REPORT = ROOT / "reports" / "executable-eighth-tranche" / "manifest.json"

# Frozen only after the complete task/fixture implementation and canonical
# report passed cross-implementation engineering review. Human attestation
# remains false in the public record.
EXPECTED_REGISTRY_SHA256 = (
    "8ef6879c5b6f4198c1b0ff2acfcffe89b6cbdd418a9aa2af2eefedfb12994736"
)
EXPECTED_CUMULATIVE_SUITE_SHA256 = (
    "b22742179e3ce3b7331469de9db0a75ddbae81a3340e2b814c8a7ab34233f0f0"
)
EXPECTED_CATALOG_SHA256 = (
    "05e4b90408a0970dfded597e5ee7813386bfdaed50a1cea301148eaabd83c297"
)
REPORT_SHA256 = (
    "822f2e20e5f73d638dff810c12aec0985145b642801975f6148b034ecf155d0e"
)
REPORT_LENGTH = 56_369


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _canonical_bytes(record: dict[str, object]) -> bytes:
    return (
        json.dumps(
            record,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def _contains_bytes(value: object) -> bool:
    if type(value) is bytes:
        return True
    if type(value) is dict:
        return any(
            _contains_bytes(key) or _contains_bytes(item)
            for key, item in value.items()
        )
    if type(value) in {list, tuple}:
        return any(_contains_bytes(item) for item in value)
    return False


def _temporary_files(parent: Path) -> list[Path]:
    return list(parent.glob(".cbds-eighth-*.tmp"))


class EighthTranchePublisherReachabilityTests(unittest.TestCase):
    """Cheap race tests that do not rebuild the fixture catalog."""

    payload = b'{"fixed":"eighth-reachability"}\n'

    def test_reachable_parent_still_publishes_and_reads_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "nested" / "manifest.json"
            REPORT_SCRIPT.atomic_publish_noreplace(report, self.payload)
            first = report.lstat()
            self.assertTrue(stat.S_ISREG(first.st_mode))
            self.assertEqual(stat.S_IMODE(first.st_mode), 0o644)
            self.assertEqual(first.st_nlink, 1)
            self.assertEqual(
                REPORT_SCRIPT._read_existing_regular(report, len(self.payload)),
                self.payload,
            )
            REPORT_SCRIPT.atomic_publish_noreplace(report, self.payload)
            second = report.lstat()
            self.assertEqual((second.st_dev, second.st_ino), (first.st_dev, first.st_ino))
            self.assertEqual(_temporary_files(report.parent), [])

    def test_extra_hardlink_during_publish_is_rejected_and_cleaned(self) -> None:
        if os.name != "posix":
            self.skipTest("descriptor-relative hard-link races require POSIX")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "manifest.json"
            attacker = root / "attacker-link"
            real_link = os.link
            raced = False

            def link_final_and_attacker(source, destination, **kwargs):
                nonlocal raced
                result = real_link(source, destination, **kwargs)
                self.assertFalse(raced)
                real_link(source, attacker.name, **kwargs)
                raced = True
                return result

            with mock.patch.object(
                REPORT_SCRIPT.os,
                "link",
                side_effect=link_final_and_attacker,
            ), self.assertRaises(
                REPORT_SCRIPT.EighthTrancheCatalogPublicationError
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(report, self.payload)

            self.assertTrue(raced)
            self.assertFalse(report.exists())
            self.assertTrue(attacker.is_file())
            self.assertEqual(attacker.read_bytes(), self.payload)
            self.assertEqual(attacker.lstat().st_nlink, 1)
            self.assertEqual(_temporary_files(root), [])

    def test_extra_hardlink_after_temp_unlink_is_rejected_and_cleaned(
        self,
    ) -> None:
        if os.name != "posix":
            self.skipTest("descriptor-relative hard-link races require POSIX")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "manifest.json"
            attacker = root / "attacker-link"
            real_link = os.link
            real_unlink = os.unlink
            raced = False

            def unlink_temp_then_link_attacker(path, **kwargs):
                nonlocal raced
                result = real_unlink(path, **kwargs)
                if (
                    not raced
                    and type(path) is str
                    and path.startswith(".cbds-eighth-")
                ):
                    parent_descriptor = kwargs["dir_fd"]
                    real_link(
                        report.name,
                        attacker.name,
                        src_dir_fd=parent_descriptor,
                        dst_dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                    raced = True
                return result

            with mock.patch.object(
                REPORT_SCRIPT.os,
                "unlink",
                side_effect=unlink_temp_then_link_attacker,
            ), self.assertRaises(
                REPORT_SCRIPT.EighthTrancheCatalogPublicationError
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(report, self.payload)

            self.assertTrue(raced)
            self.assertFalse(report.exists())
            self.assertTrue(attacker.is_file())
            self.assertEqual(attacker.read_bytes(), self.payload)
            self.assertEqual(attacker.lstat().st_nlink, 1)
            self.assertEqual(_temporary_files(root), [])

    def test_replaced_temp_name_survives_fail_closed_cleanup(self) -> None:
        if os.name != "posix":
            self.skipTest("descriptor-relative temp-name races require POSIX")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "manifest.json"
            attacker_payload = b'{"attacker":"temporary-replacement"}\n'
            real_cleanup = REPORT_SCRIPT._unlink_temporary_if_same
            real_unlink = os.unlink
            replacement: Path | None = None
            staged_identity: tuple[int, int] | None = None
            raced = False

            def replace_temp_before_authenticated_unlink(
                parent_descriptor,
                temporary_name,
                created,
                *,
                fail_closed,
            ):
                nonlocal replacement, staged_identity, raced
                if fail_closed and not raced:
                    staged = os.stat(
                        temporary_name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                    staged_identity = (staged.st_dev, staged.st_ino)
                    real_unlink(temporary_name, dir_fd=parent_descriptor)
                    descriptor = os.open(
                        temporary_name,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                        dir_fd=parent_descriptor,
                    )
                    try:
                        REPORT_SCRIPT._write_all(descriptor, attacker_payload)
                        os.fchmod(descriptor, 0o644)
                    finally:
                        os.close(descriptor)
                    replacement = root / temporary_name
                    raced = True
                return real_cleanup(
                    parent_descriptor,
                    temporary_name,
                    created,
                    fail_closed=fail_closed,
                )

            with mock.patch.object(
                REPORT_SCRIPT,
                "_unlink_temporary_if_same",
                side_effect=replace_temp_before_authenticated_unlink,
            ), self.assertRaisesRegex(
                REPORT_SCRIPT.EighthTrancheCatalogPublicationError,
                "no longer resolves to the created inode",
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(report, self.payload)

            self.assertTrue(raced)
            self.assertFalse(report.exists())
            self.assertIsNotNone(replacement)
            self.assertIsNotNone(staged_identity)
            if replacement is None or staged_identity is None:
                self.fail("temp-name replacement race did not record identities")
            self.assertTrue(replacement.is_file())
            self.assertEqual(replacement.read_bytes(), attacker_payload)
            replacement_metadata = replacement.lstat()
            self.assertNotEqual(
                (replacement_metadata.st_dev, replacement_metadata.st_ino),
                staged_identity,
            )
            self.assertEqual(replacement_metadata.st_nlink, 1)
            self.assertEqual(list(root.iterdir()), [replacement])

    def test_changed_preexisting_final_is_rejected_but_never_deleted(self) -> None:
        if os.name != "posix":
            self.skipTest("descriptor-relative publication races require POSIX")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "manifest.json"
            report.write_bytes(self.payload)
            report.chmod(0o644)
            real_unlink = os.unlink
            raced = False
            attacker_payload = b'{"attacker":"preserved"}\n'

            def unlink_temp_then_change_existing(path, **kwargs):
                nonlocal raced
                result = real_unlink(path, **kwargs)
                if (
                    not raced
                    and type(path) is str
                    and path.startswith(".cbds-eighth-")
                ):
                    report.write_bytes(attacker_payload)
                    report.chmod(0o644)
                    raced = True
                return result

            with mock.patch.object(
                REPORT_SCRIPT.os,
                "unlink",
                side_effect=unlink_temp_then_change_existing,
            ), self.assertRaises(
                REPORT_SCRIPT.EighthTrancheCatalogPublicationError
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(report, self.payload)

            self.assertTrue(raced)
            self.assertTrue(report.is_file())
            self.assertEqual(report.read_bytes(), attacker_payload)
            self.assertEqual(report.lstat().st_nlink, 1)
            self.assertEqual(_temporary_files(root), [])

    def test_published_cleanup_preserves_replacement_visible_at_authentication(
        self,
    ) -> None:
        if os.name != "posix":
            self.skipTest("descriptor-relative publication cleanup requires POSIX")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged = root / "staged.json"
            staged.write_bytes(self.payload)
            staged.chmod(0o644)
            expected = staged.lstat()
            report = root / "manifest.json"
            os.link(staged, report)
            report.unlink()
            attacker_payload = b'{"attacker":"visible-before-stat"}\n'
            report.write_bytes(attacker_payload)
            report.chmod(0o644)
            parent = os.open(
                root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                with self.assertRaisesRegex(
                    REPORT_SCRIPT.EighthTrancheCatalogPublicationError,
                    "no longer names the staged inode",
                ):
                    REPORT_SCRIPT._unlink_published_if_same(
                        parent,
                        report.name,
                        expected,
                    )
            finally:
                os.close(parent)

            self.assertTrue(report.is_file())
            self.assertEqual(report.read_bytes(), attacker_payload)
            self.assertEqual(report.lstat().st_nlink, 1)
            self.assertEqual(staged.read_bytes(), self.payload)

    def test_parent_displacement_during_link_removes_only_our_publication(
        self,
    ) -> None:
        if os.name != "posix":
            self.skipTest("descriptor-relative parent races require POSIX")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "parent"
            parent.mkdir()
            parked = root / "parked"
            report = parent / "manifest.json"
            real_link = os.link
            displaced = False

            def link_then_displace(*args, **kwargs):
                nonlocal displaced
                result = real_link(*args, **kwargs)
                self.assertFalse(displaced)
                parent.rename(parked)
                parent.mkdir()
                displaced = True
                return result

            with mock.patch.object(
                REPORT_SCRIPT.os, "link", side_effect=link_then_displace
            ), self.assertRaisesRegex(
                REPORT_SCRIPT.EighthTrancheCatalogPublicationError,
                "no longer reachable",
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(report, self.payload)

            self.assertTrue(displaced)
            self.assertFalse(report.exists())
            self.assertFalse((parked / report.name).exists())
            self.assertEqual(_temporary_files(parent), [])
            self.assertEqual(_temporary_files(parked), [])
            self.assertEqual(list(parent.iterdir()), [])
            self.assertEqual(list(parked.iterdir()), [])

    def test_parent_displacement_during_existing_read_fails_closed(
        self,
    ) -> None:
        if os.name != "posix":
            self.skipTest("descriptor-relative parent races require POSIX")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "parent"
            parent.mkdir()
            parked = root / "parked"
            report = parent / "manifest.json"
            report.write_bytes(self.payload)
            report.chmod(0o644)
            real_read = os.read
            displaced = False

            def read_then_displace(*args, **kwargs):
                nonlocal displaced
                result = real_read(*args, **kwargs)
                if not displaced:
                    parent.rename(parked)
                    parent.mkdir()
                    displaced = True
                return result

            with mock.patch.object(
                REPORT_SCRIPT.os, "read", side_effect=read_then_displace
            ), self.assertRaisesRegex(
                REPORT_SCRIPT.EighthTrancheCatalogPublicationError,
                "no longer reachable",
            ):
                REPORT_SCRIPT._read_existing_regular(report, len(self.payload))

            self.assertTrue(displaced)
            self.assertFalse(report.exists())
            self.assertFalse((parent / report.name).exists())
            # No-replace semantics preserve the pre-existing inode even though
            # its containing directory was displaced by the simulated racer.
            self.assertEqual((parked / report.name).read_bytes(), self.payload)
            self.assertEqual(_temporary_files(parent), [])
            self.assertEqual(_temporary_files(parked), [])


class EighthTrancheCatalogReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = build_eighth_tranche_fixture_catalog()
        cls.record = cls.catalog.to_hash_only_record()
        cls.payload = _canonical_bytes(cls.record)

    def test_builder_serializes_only_the_central_canonical_projection(self) -> None:
        with mock.patch.object(
            REPORT_SCRIPT,
            "build_eighth_tranche_fixture_catalog",
            return_value=self.catalog,
        ) as central_builder:
            first = REPORT_SCRIPT.canonical_eighth_tranche_catalog_bytes()
            second = REPORT_SCRIPT.canonical_eighth_tranche_catalog_bytes()
        self.assertEqual(central_builder.call_count, 2)
        self.assertEqual(first, self.payload)
        self.assertEqual(second, self.payload)
        parsed = json.loads(
            first.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"nonfinite JSON constant: {value}")
            ),
        )
        self.assertEqual(parsed, self.record)
        self.assertEqual(_canonical_bytes(parsed), first)

    def test_projection_binds_hashes_and_contains_no_sensitive_fields(self) -> None:
        self.assertFalse(_contains_bytes(self.record))
        encoded = self.payload.decode("utf-8", errors="strict")
        self.assertEqual(
            self.record["record_type"],
            "cbds.executable-fixture-eighth-tranche-catalog",
        )
        self.assertEqual(
            self.record["added_registry_sha256"], EXPECTED_REGISTRY_SHA256
        )
        self.assertEqual(
            self.record["cumulative_suite_sha256"],
            EXPECTED_CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(
            self.record["catalog_sha256"], EXPECTED_CATALOG_SHA256
        )
        self.assertEqual(self.record["added_task_count"], 20)
        self.assertEqual(self.record["cumulative_task_count"], 340)
        self.assertEqual(self.record["added_fixture_count"], 100)
        self.assertEqual(self.record["cumulative_fixture_count"], 1_700)
        self.assertEqual(len(self.record["added_tasks"]), 20)
        self.assertEqual(len(self.record["added_fixtures"]), 100)
        generators = self.record["family_generators"]
        self.assertEqual(len(generators), 1)
        self.assertEqual(
            generators[0]["family_id"], "collision-safe-batch-rename"
        )
        self.assertEqual(generators[0]["generator_version"], "1.0.0")
        self.assertEqual(
            generators[0]["semantic_verifier_identity"],
            "verify-collision-safe-batch-rename-v1",
        )
        self.assertEqual(generators[0]["output_maximum_bytes"], 1_048_576)
        for forbidden in (
            '"content"',
            '"inputs"',
            '"outputs"',
            '"prompt"',
            '"path"',
            '"answer"',
            "input/",
            "output/",
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertIs(self.record["public_method_development"], True)
        self.assertIs(self.record["sealed"], False)
        self.assertIs(
            self.record["independent_human_review_attested"], False
        )
        self.assertIs(self.record["candidate_execution_authorized"], False)
        self.assertIs(self.record["model_selection_eligible"], False)
        self.assertIs(self.record["claim_authorized"], False)

    def test_publication_is_idempotent_exact_mode_link_count_and_no_replace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "nested" / "eighth-catalog.json"
            REPORT_SCRIPT.atomic_publish_noreplace(report, self.payload)
            first = report.lstat()
            self.assertTrue(stat.S_ISREG(first.st_mode))
            self.assertEqual(stat.S_IMODE(first.st_mode), 0o644)
            self.assertEqual(first.st_nlink, 1)
            self.assertEqual(report.read_bytes(), self.payload)
            self.assertEqual(_temporary_files(report.parent), [])

            REPORT_SCRIPT.atomic_publish_noreplace(report, self.payload)
            second = report.lstat()
            self.assertEqual((second.st_dev, second.st_ino), (first.st_dev, first.st_ino))
            self.assertEqual(stat.S_IMODE(second.st_mode), 0o644)
            self.assertEqual(second.st_nlink, 1)
            with self.assertRaisesRegex(
                REPORT_SCRIPT.EighthTrancheCatalogPublicationError,
                "differs",
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(
                    report, self.payload + b"different"
                )
            self.assertEqual(report.read_bytes(), self.payload)
            self.assertEqual(_temporary_files(report.parent), [])

    def test_existing_final_symlink_is_rejected_without_touching_victim(self) -> None:
        if os.name != "posix":
            self.skipTest("no-follow symlink publication requires POSIX")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            victim = root / "victim.json"
            victim.write_bytes(b"outside-victim\n")
            report = root / "manifest.json"
            report.symlink_to(victim)
            with self.assertRaises(
                REPORT_SCRIPT.EighthTrancheCatalogPublicationError
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(report, self.payload)
            self.assertTrue(report.is_symlink())
            self.assertEqual(victim.read_bytes(), b"outside-victim\n")
            self.assertEqual(_temporary_files(root), [])

    def test_symlink_parent_is_rejected_without_publishing_through_it(self) -> None:
        if os.name != "posix":
            self.skipTest("no-follow parent traversal requires POSIX")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            victim = root / "victim"
            victim.mkdir()
            alias = root / "alias"
            alias.symlink_to(victim, target_is_directory=True)
            report = alias / "nested" / "manifest.json"
            with self.assertRaises(
                REPORT_SCRIPT.EighthTrancheCatalogPublicationError
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(report, self.payload)
            self.assertFalse((victim / "nested").exists())
            self.assertEqual(list(victim.iterdir()), [])
            self.assertTrue(alias.is_symlink())

    def test_existing_hardlink_and_wrong_mode_are_rejected(self) -> None:
        if os.name != "posix":
            self.skipTest("hard-link publication checks require POSIX")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            original = root / "original.json"
            original.write_bytes(self.payload)
            original.chmod(0o644)
            hardlink = root / "hardlink.json"
            os.link(original, hardlink)
            self.assertEqual(hardlink.lstat().st_nlink, 2)
            with self.assertRaisesRegex(
                REPORT_SCRIPT.EighthTrancheCatalogPublicationError,
                "link-count-one",
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(hardlink, self.payload)
            self.assertEqual(original.read_bytes(), self.payload)
            self.assertEqual(hardlink.lstat().st_nlink, 2)

            wrong_mode = root / "wrong-mode.json"
            wrong_mode.write_bytes(self.payload)
            wrong_mode.chmod(0o600)
            with self.assertRaisesRegex(
                REPORT_SCRIPT.EighthTrancheCatalogPublicationError,
                "mode-0644",
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(wrong_mode, self.payload)
            self.assertEqual(stat.S_IMODE(wrong_mode.lstat().st_mode), 0o600)
            self.assertEqual(wrong_mode.read_bytes(), self.payload)
            self.assertEqual(_temporary_files(root), [])

    def test_existing_fifo_and_directory_are_rejected_without_blocking(self) -> None:
        if os.name != "posix" or not hasattr(os, "mkfifo"):
            self.skipTest("FIFO publication checks require POSIX mkfifo")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fifo = root / "fifo.json"
            os.mkfifo(fifo, 0o644)
            with self.assertRaises(
                REPORT_SCRIPT.EighthTrancheCatalogPublicationError
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(fifo, self.payload)
            self.assertTrue(stat.S_ISFIFO(fifo.lstat().st_mode))

            directory = root / "directory.json"
            directory.mkdir(mode=0o755)
            with self.assertRaises(
                REPORT_SCRIPT.EighthTrancheCatalogPublicationError
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(directory, self.payload)
            self.assertTrue(directory.is_dir())
            self.assertEqual(_temporary_files(root), [])

    def test_publication_rejects_nonexact_payloads_and_invalid_path_types(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "manifest.json"
            with self.assertRaisesRegex(
                REPORT_SCRIPT.EighthTrancheCatalogPublicationError,
                "Path and immutable bytes",
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(  # type: ignore[arg-type]
                    str(report), self.payload
                )
            with self.assertRaisesRegex(
                REPORT_SCRIPT.EighthTrancheCatalogPublicationError,
                "Path and immutable bytes",
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(  # type: ignore[arg-type]
                    report, bytearray(self.payload)
                )
            self.assertFalse(report.exists())

    def test_cli_uses_central_projection_and_checks_missing_or_different(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            REPORT_SCRIPT,
            "canonical_eighth_tranche_catalog_bytes",
            return_value=self.payload,
        ) as central_projection:
            report = Path(temporary) / "caller" / "manifest.json"
            self.assertEqual(REPORT_SCRIPT.main(["--output", str(report)]), 0)
            self.assertEqual(
                REPORT_SCRIPT.main(["--output", str(report), "--check"]), 0
            )
            info = report.lstat()
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o644)
            self.assertEqual(info.st_nlink, 1)
            self.assertEqual(report.read_bytes(), self.payload)

            missing = Path(temporary) / "missing.json"
            with self.assertRaisesRegex(SystemExit, "does not exist"):
                REPORT_SCRIPT.main(["--output", str(missing), "--check"])
            report.write_bytes(b"different\n")
            report.chmod(0o644)
            with self.assertRaisesRegex(SystemExit, "differs"):
                REPORT_SCRIPT.main(["--output", str(report)])
            self.assertEqual(report.read_bytes(), b"different\n")
        self.assertEqual(central_projection.call_count, 4)

    def test_checked_manifest_has_frozen_identity_and_safe_file_shape(self) -> None:
        for marker in (
            EXPECTED_REGISTRY_SHA256,
            EXPECTED_CUMULATIVE_SUITE_SHA256,
            EXPECTED_CATALOG_SHA256,
            REPORT_SHA256,
        ):
            self.assertRegex(marker, r"\A[0-9a-f]{64}\Z")
        self.assertGreater(REPORT_LENGTH, 0)
        info = REPORT.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o644)
        self.assertEqual(info.st_nlink, 1)
        payload = REPORT.read_bytes()
        self.assertEqual(len(payload), REPORT_LENGTH)
        self.assertEqual(sha256(payload).hexdigest(), REPORT_SHA256)
        self.assertEqual(payload, self.payload)
        observed = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"nonfinite JSON constant: {value}")
            ),
        )
        self.assertEqual(observed, self.record)


if __name__ == "__main__":
    unittest.main()
