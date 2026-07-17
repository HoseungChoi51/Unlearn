from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


from cbds.hash_only_report_publication import (
    HashOnlyReportPublicationError,
    atomic_publish_noreplace,
    read_existing_regular,
)
import cbds.hash_only_report_publication as publication


PAYLOAD = b'{"hash_only":true,"sha256":"0123456789abcdef"}\n'
PREFIX = ".cbds-hash-report-"


def temporary_files(parent: Path) -> list[Path]:
    if not parent.is_dir():
        return []
    return sorted(
        (
            child
            for child in parent.iterdir()
            if child.name.startswith(PREFIX)
            and child.name.endswith(".tmp")
        ),
        key=lambda child: child.name,
    )


def descriptor_count() -> int | None:
    proc = Path("/proc/self/fd")
    return len(list(proc.iterdir())) if proc.is_dir() else None


class HashOnlyReportReadTests(unittest.TestCase):
    def test_missing_parent_or_entry_reads_as_absent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertIsNone(
                read_existing_regular(
                    root / "missing-parent" / "report.json",
                    len(PAYLOAD),
                )
            )
            self.assertIsNone(
                read_existing_regular(
                    root / "missing.json",
                    len(PAYLOAD),
                )
            )

    def test_reads_one_bounded_stable_mode_0644_link_count_one_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report.json"
            report.write_bytes(PAYLOAD)
            report.chmod(0o644)
            self.assertEqual(
                read_existing_regular(report, len(PAYLOAD)),
                PAYLOAD,
            )
            with self.assertRaisesRegex(
                HashOnlyReportPublicationError,
                "byte bound",
            ):
                read_existing_regular(report, len(PAYLOAD) - 1)

    def test_read_rejects_symlink_hardlink_wrong_mode_fifo_and_directory(self) -> None:
        if os.name != "posix":
            self.skipTest("no-follow shape checks require POSIX")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            victim = root / "victim"
            victim.write_bytes(b"victim-must-not-be-read")
            victim.chmod(0o644)

            symlink = root / "symlink"
            symlink.symlink_to(victim)
            original = root / "original"
            original.write_bytes(PAYLOAD)
            original.chmod(0o644)
            hardlink = root / "hardlink"
            os.link(original, hardlink)
            wrong_mode = root / "wrong-mode"
            wrong_mode.write_bytes(PAYLOAD)
            wrong_mode.chmod(0o600)
            fifo = root / "fifo"
            if hasattr(os, "mkfifo"):
                os.mkfifo(fifo, 0o644)
            directory = root / "directory"
            directory.mkdir()

            paths = [symlink, hardlink, wrong_mode, directory]
            if hasattr(os, "mkfifo"):
                paths.append(fifo)
            for path in paths:
                with self.subTest(path=path.name), self.assertRaises(
                    HashOnlyReportPublicationError
                ):
                    read_existing_regular(path, len(PAYLOAD))

            self.assertTrue(symlink.is_symlink())
            self.assertEqual(victim.read_bytes(), b"victim-must-not-be-read")
            self.assertEqual(original.lstat().st_nlink, 2)
            self.assertEqual(stat.S_IMODE(wrong_mode.lstat().st_mode), 0o600)

    def test_read_detects_same_inode_mutation_during_bounded_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report.json"
            report.write_bytes(PAYLOAD)
            report.chmod(0o644)
            real_read = publication.os.read
            mutated = False

            def read_then_mutate(descriptor: int, size: int) -> bytes:
                nonlocal mutated
                chunk = real_read(descriptor, size)
                if chunk and not mutated:
                    report.write_bytes(b"x" * len(PAYLOAD))
                    report.chmod(0o644)
                    mutated = True
                return chunk

            with mock.patch.object(
                publication.os,
                "read",
                side_effect=read_then_mutate,
            ), self.assertRaises(HashOnlyReportPublicationError):
                read_existing_regular(report, len(PAYLOAD))
            self.assertTrue(mutated)

    def test_read_and_publish_reject_a_symlink_parent_without_visiting_it(self) -> None:
        if os.name != "posix":
            self.skipTest("no-follow parent traversal requires POSIX")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            victim = root / "victim"
            victim.mkdir()
            sentinel = victim / "sentinel"
            sentinel.write_bytes(b"preserve")
            alias = root / "alias"
            alias.symlink_to(victim, target_is_directory=True)
            report = alias / "nested" / "report.json"

            with self.assertRaises(HashOnlyReportPublicationError):
                read_existing_regular(report, len(PAYLOAD))
            with self.assertRaises(HashOnlyReportPublicationError):
                atomic_publish_noreplace(report, PAYLOAD, PREFIX)

            self.assertTrue(alias.is_symlink())
            self.assertEqual(sentinel.read_bytes(), b"preserve")
            self.assertFalse((victim / "nested").exists())

    def test_public_argument_shapes_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report.json"
            for bad_maximum in (-1, True, 1.5):
                with self.subTest(maximum=bad_maximum), self.assertRaises(
                    HashOnlyReportPublicationError
                ):
                    read_existing_regular(  # type: ignore[arg-type]
                        report,
                        bad_maximum,
                    )
            with self.assertRaises(HashOnlyReportPublicationError):
                read_existing_regular(  # type: ignore[arg-type]
                    str(report),
                    len(PAYLOAD),
                )
            with self.assertRaises(HashOnlyReportPublicationError):
                atomic_publish_noreplace(  # type: ignore[arg-type]
                    str(report),
                    PAYLOAD,
                    PREFIX,
                )
            with self.assertRaises(HashOnlyReportPublicationError):
                atomic_publish_noreplace(  # type: ignore[arg-type]
                    report,
                    bytearray(PAYLOAD),
                    PREFIX,
                )
            for prefix in (
                "",
                "../escape-",
                "slash/prefix-",
                "space prefix-",
                "x" * 129,
            ):
                with self.subTest(prefix=prefix), self.assertRaises(
                    HashOnlyReportPublicationError
                ):
                    atomic_publish_noreplace(report, PAYLOAD, prefix)
            self.assertFalse(report.exists())

    @unittest.skipUnless(
        Path("/proc/self/fd").is_dir(),
        "fault-injected read cleanup requires procfs",
    )
    def test_read_failure_closes_its_file_and_parent_descriptors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report.json"
            report.write_bytes(PAYLOAD)
            report.chmod(0o644)
            before = descriptor_count()
            with mock.patch.object(
                publication.os,
                "read",
                side_effect=OSError("injected read failure"),
            ), self.assertRaises(HashOnlyReportPublicationError):
                read_existing_regular(report, len(PAYLOAD))
            self.assertEqual(descriptor_count(), before)

    def test_parent_displacement_during_read_fails_but_preserves_existing(
        self,
    ) -> None:
        if os.name != "posix":
            self.skipTest("descriptor-relative parent races require POSIX")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "parent"
            parent.mkdir()
            parked = root / "parked"
            report = parent / "report.json"
            report.write_bytes(PAYLOAD)
            report.chmod(0o644)
            real_read = publication.os.read
            displaced = False

            def read_then_displace(
                descriptor: int,
                size: int,
            ) -> bytes:
                nonlocal displaced
                result = real_read(descriptor, size)
                if not displaced:
                    parent.rename(parked)
                    parent.mkdir()
                    displaced = True
                return result

            with mock.patch.object(
                publication.os,
                "read",
                side_effect=read_then_displace,
            ), self.assertRaisesRegex(
                HashOnlyReportPublicationError,
                "no longer reachable",
            ):
                read_existing_regular(report, len(PAYLOAD))

            self.assertTrue(displaced)
            self.assertFalse(report.exists())
            self.assertEqual((parked / report.name).read_bytes(), PAYLOAD)
            self.assertEqual(list(parent.iterdir()), [])


class HashOnlyReportPublicationTests(unittest.TestCase):
    def test_publication_is_exact_durable_idempotent_and_no_replace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "nested" / "report.json"
            atomic_publish_noreplace(report, PAYLOAD, PREFIX)
            first = report.lstat()
            self.assertTrue(stat.S_ISREG(first.st_mode))
            self.assertEqual(stat.S_IMODE(first.st_mode), 0o644)
            self.assertEqual(first.st_nlink, 1)
            self.assertEqual(report.read_bytes(), PAYLOAD)
            self.assertEqual(temporary_files(report.parent), [])

            atomic_publish_noreplace(report, PAYLOAD, PREFIX)
            second = report.lstat()
            self.assertEqual(
                (second.st_dev, second.st_ino),
                (first.st_dev, first.st_ino),
            )
            with self.assertRaisesRegex(
                HashOnlyReportPublicationError,
                "differs",
            ):
                atomic_publish_noreplace(
                    report,
                    PAYLOAD + b"different",
                    PREFIX,
                )
            self.assertEqual(report.read_bytes(), PAYLOAD)
            self.assertEqual(temporary_files(report.parent), [])

    def test_short_writes_are_completed_and_file_and_parent_are_fsynced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report.json"
            real_write = publication.os.write
            real_fsync = publication.os.fsync
            fsynced_kinds: list[str] = []
            write_calls = 0

            def short_write(descriptor: int, payload: object) -> int:
                nonlocal write_calls
                write_calls += 1
                selected = memoryview(payload)[:3]
                return real_write(descriptor, selected)

            def recording_fsync(descriptor: int) -> None:
                mode = os.fstat(descriptor).st_mode
                fsynced_kinds.append(
                    "directory" if stat.S_ISDIR(mode) else "file"
                )
                real_fsync(descriptor)

            with mock.patch.object(
                publication.os,
                "write",
                side_effect=short_write,
            ), mock.patch.object(
                publication.os,
                "fsync",
                side_effect=recording_fsync,
            ):
                atomic_publish_noreplace(report, PAYLOAD, PREFIX)

            self.assertGreater(write_calls, 1)
            self.assertIn("file", fsynced_kinds)
            self.assertGreaterEqual(fsynced_kinds.count("directory"), 2)
            self.assertEqual(report.read_bytes(), PAYLOAD)

    def test_temporary_name_uses_128_bits_and_exclusive_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report.json"
            with mock.patch.object(
                publication.secrets,
                "token_hex",
                wraps=publication.secrets.token_hex,
            ) as token_hex:
                atomic_publish_noreplace(report, PAYLOAD, PREFIX)
            token_hex.assert_called_once_with(16)
            self.assertEqual(temporary_files(root), [])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report.json"
            token = "0" * 32
            occupied = root / f"{PREFIX}{token}.tmp"
            occupied.write_bytes(b"attacker")
            occupied.chmod(0o644)
            with mock.patch.object(
                publication.secrets,
                "token_hex",
                return_value=token,
            ), self.assertRaisesRegex(
                HashOnlyReportPublicationError,
                "cannot be created",
            ):
                atomic_publish_noreplace(report, PAYLOAD, PREFIX)
            self.assertEqual(occupied.read_bytes(), b"attacker")
            self.assertFalse(report.exists())

    @unittest.skipUnless(
        Path("/proc/self/fd").is_dir(),
        "fault-injected descriptor authentication requires procfs",
    )
    def test_immediate_post_open_fstat_failure_preserves_replacement_and_closes_fds(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report.json"
            attacker_payload = b"concurrent temporary replacement"
            real_fstat = publication.os.fstat
            captured_descriptor: int | None = None
            replacement: Path | None = None
            before = descriptor_count()

            def fail_created_descriptor(descriptor: int) -> os.stat_result:
                nonlocal captured_descriptor, replacement
                try:
                    opened = Path(f"/proc/self/fd/{descriptor}").resolve(
                        strict=True
                    )
                except OSError:
                    opened = None
                if (
                    captured_descriptor is None
                    and opened is not None
                    and opened.name.startswith(PREFIX)
                    and opened.name.endswith(".tmp")
                ):
                    captured_descriptor = descriptor
                    replacement = opened
                    opened.unlink()
                    opened.write_bytes(attacker_payload)
                    opened.chmod(0o644)
                    raise OSError("injected immediate fstat failure")
                return real_fstat(descriptor)

            with mock.patch.object(
                publication.os,
                "fstat",
                side_effect=fail_created_descriptor,
            ), self.assertRaisesRegex(
                HashOnlyReportPublicationError,
                "left untouched",
            ):
                atomic_publish_noreplace(report, PAYLOAD, PREFIX)

            self.assertIsNotNone(captured_descriptor)
            self.assertIsNotNone(replacement)
            if captured_descriptor is None or replacement is None:
                self.fail("temporary descriptor fault was not injected")
            with self.assertRaises(OSError):
                real_fstat(captured_descriptor)
            self.assertTrue(replacement.is_file())
            self.assertEqual(replacement.read_bytes(), attacker_payload)
            self.assertEqual(stat.S_IMODE(replacement.lstat().st_mode), 0o644)
            self.assertFalse(report.exists())
            self.assertEqual(descriptor_count(), before)

    @unittest.skipUnless(
        Path("/proc/self/fd").is_dir(),
        "fault-injected descriptor cleanup requires procfs",
    )
    def test_authenticated_failure_paths_remove_only_their_temp_and_close_fds(
        self,
    ) -> None:
        cases = (
            "fchmod",
            "write",
            "file-fsync",
            "directory-fsync",
            "second-fstat",
            "link",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                report = root / "report.json"
                before = descriptor_count()
                stack = []
                if case == "fchmod":
                    stack.append(
                        mock.patch.object(
                            publication.os,
                            "fchmod",
                            side_effect=OSError("injected fchmod failure"),
                        )
                    )
                elif case == "write":
                    stack.append(
                        mock.patch.object(
                            publication.os,
                            "write",
                            side_effect=OSError("injected write failure"),
                        )
                    )
                elif case == "file-fsync":
                    real_fsync = publication.os.fsync
                    failed = False

                    def fail_file_fsync(descriptor: int) -> None:
                        nonlocal failed
                        if (
                            not failed
                            and stat.S_ISREG(os.fstat(descriptor).st_mode)
                        ):
                            failed = True
                            raise OSError("injected file fsync failure")
                        real_fsync(descriptor)

                    stack.append(
                        mock.patch.object(
                            publication.os,
                            "fsync",
                            side_effect=fail_file_fsync,
                        )
                    )
                elif case == "directory-fsync":
                    real_fsync = publication.os.fsync
                    failed = False

                    def fail_directory_fsync(descriptor: int) -> None:
                        nonlocal failed
                        if (
                            not failed
                            and stat.S_ISDIR(os.fstat(descriptor).st_mode)
                        ):
                            failed = True
                            raise OSError(
                                "injected directory fsync failure"
                            )
                        real_fsync(descriptor)

                    stack.append(
                        mock.patch.object(
                            publication.os,
                            "fsync",
                            side_effect=fail_directory_fsync,
                        )
                    )
                elif case == "second-fstat":
                    real_fstat = publication.os.fstat
                    temporary_calls = 0

                    def fail_second_temporary_fstat(
                        descriptor: int,
                    ) -> os.stat_result:
                        nonlocal temporary_calls
                        try:
                            opened = Path(
                                f"/proc/self/fd/{descriptor}"
                            ).resolve(strict=True)
                        except OSError:
                            opened = None
                        if (
                            opened is not None
                            and opened.name.startswith(PREFIX)
                        ):
                            temporary_calls += 1
                            if temporary_calls == 2:
                                raise OSError(
                                    "injected second fstat failure"
                                )
                        return real_fstat(descriptor)

                    stack.append(
                        mock.patch.object(
                            publication.os,
                            "fstat",
                            side_effect=fail_second_temporary_fstat,
                        )
                    )
                else:
                    stack.append(
                        mock.patch.object(
                            publication.os,
                            "link",
                            side_effect=OSError("injected link failure"),
                        )
                    )

                try:
                    for selected in stack:
                        selected.start()
                    with self.assertRaises(HashOnlyReportPublicationError):
                        atomic_publish_noreplace(report, PAYLOAD, PREFIX)
                finally:
                    for selected in reversed(stack):
                        selected.stop()
                self.assertFalse(report.exists())
                self.assertEqual(temporary_files(root), [])
                self.assertEqual(descriptor_count(), before)

    def test_extra_hardlink_is_rejected_and_only_our_names_are_cleaned(self) -> None:
        if os.name != "posix":
            self.skipTest("descriptor-relative hard-link races require POSIX")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report.json"
            attacker = root / "attacker-link"
            real_link = publication.os.link
            raced = False

            def link_final_and_attacker(
                source: str,
                destination: str,
                **kwargs: object,
            ) -> None:
                nonlocal raced
                real_link(source, destination, **kwargs)
                self.assertFalse(raced)
                real_link(source, attacker.name, **kwargs)
                raced = True

            with mock.patch.object(
                publication.os,
                "link",
                side_effect=link_final_and_attacker,
            ), self.assertRaises(HashOnlyReportPublicationError):
                atomic_publish_noreplace(report, PAYLOAD, PREFIX)

            self.assertTrue(raced)
            self.assertFalse(report.exists())
            self.assertTrue(attacker.is_file())
            self.assertEqual(attacker.read_bytes(), PAYLOAD)
            self.assertEqual(attacker.lstat().st_nlink, 1)
            self.assertEqual(temporary_files(root), [])

    def test_replaced_temporary_name_survives_authenticated_cleanup(self) -> None:
        if os.name != "posix":
            self.skipTest("descriptor-relative temp races require POSIX")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report.json"
            attacker_payload = b"attacker temporary replacement"
            real_cleanup = publication._unlink_temporary_if_same
            real_unlink = publication.os.unlink
            replacement: Path | None = None
            raced = False

            def replace_before_cleanup(
                parent_descriptor: int,
                temporary_name: str,
                created: os.stat_result,
                *,
                fail_closed: bool,
            ) -> bool:
                nonlocal replacement, raced
                if fail_closed and not raced:
                    real_unlink(
                        temporary_name,
                        dir_fd=parent_descriptor,
                    )
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
                        os.write(descriptor, attacker_payload)
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
                publication,
                "_unlink_temporary_if_same",
                side_effect=replace_before_cleanup,
            ), self.assertRaisesRegex(
                HashOnlyReportPublicationError,
                "no longer resolves",
            ):
                atomic_publish_noreplace(report, PAYLOAD, PREFIX)

            self.assertTrue(raced)
            self.assertFalse(report.exists())
            self.assertIsNotNone(replacement)
            if replacement is None:
                self.fail("temporary replacement was not recorded")
            self.assertEqual(replacement.read_bytes(), attacker_payload)
            self.assertEqual(list(root.iterdir()), [replacement])

    def test_changed_preexisting_final_is_rejected_and_never_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report.json"
            report.write_bytes(PAYLOAD)
            report.chmod(0o644)
            attacker_payload = b"x" * len(PAYLOAD)
            real_cleanup = publication._unlink_temporary_if_same
            raced = False

            def cleanup_then_change_existing(*args: object, **kwargs: object) -> bool:
                nonlocal raced
                result = real_cleanup(*args, **kwargs)
                if kwargs.get("fail_closed") is True and not raced:
                    report.write_bytes(attacker_payload)
                    report.chmod(0o644)
                    raced = True
                return result

            with mock.patch.object(
                publication,
                "_unlink_temporary_if_same",
                side_effect=cleanup_then_change_existing,
            ), self.assertRaises(HashOnlyReportPublicationError):
                atomic_publish_noreplace(report, PAYLOAD, PREFIX)

            self.assertTrue(raced)
            self.assertTrue(report.is_file())
            self.assertEqual(report.read_bytes(), attacker_payload)
            self.assertEqual(report.lstat().st_nlink, 1)
            self.assertEqual(temporary_files(root), [])

    def test_published_cleanup_preserves_a_visible_final_replacement(self) -> None:
        if os.name != "posix":
            self.skipTest("descriptor-relative replacement races require POSIX")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report.json"
            attacker_payload = b"attacker final replacement"
            real_authenticate = publication._authenticate_staged_after_link
            raced = False

            def authenticate_then_replace(*args: object, **kwargs: object) -> None:
                nonlocal raced
                real_authenticate(*args, **kwargs)
                report.unlink()
                report.write_bytes(attacker_payload)
                report.chmod(0o644)
                raced = True
                raise HashOnlyReportPublicationError(
                    "injected failure after final replacement"
                )

            with mock.patch.object(
                publication,
                "_authenticate_staged_after_link",
                side_effect=authenticate_then_replace,
            ), self.assertRaisesRegex(
                HashOnlyReportPublicationError,
                "no longer names the staged inode",
            ):
                atomic_publish_noreplace(report, PAYLOAD, PREFIX)

            self.assertTrue(raced)
            self.assertTrue(report.is_file())
            self.assertEqual(report.read_bytes(), attacker_payload)
            self.assertEqual(report.lstat().st_nlink, 1)
            self.assertEqual(temporary_files(root), [])

    def test_parent_displacement_fails_and_removes_publication_from_pinned_parent(
        self,
    ) -> None:
        if os.name != "posix":
            self.skipTest("descriptor-relative parent races require POSIX")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "parent"
            parent.mkdir()
            parked = root / "parked"
            report = parent / "report.json"
            real_link = publication.os.link
            displaced = False

            def link_then_displace(*args: object, **kwargs: object) -> None:
                nonlocal displaced
                real_link(*args, **kwargs)
                parent.rename(parked)
                parent.mkdir()
                displaced = True

            with mock.patch.object(
                publication.os,
                "link",
                side_effect=link_then_displace,
            ), self.assertRaisesRegex(
                HashOnlyReportPublicationError,
                "no longer reachable",
            ):
                atomic_publish_noreplace(report, PAYLOAD, PREFIX)

            self.assertTrue(displaced)
            self.assertFalse(report.exists())
            self.assertFalse((parked / report.name).exists())
            self.assertEqual(list(parent.iterdir()), [])
            self.assertEqual(list(parked.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
