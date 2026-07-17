from __future__ import annotations

from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

SCRIPT_PATH = (
    ROOT / "scripts" / "build_executable_fifteenth_tranche_catalog.py"
)
SCRIPT_SPEC = importlib.util.spec_from_file_location(
    "cbds_build_executable_fifteenth_tranche_catalog",
    SCRIPT_PATH,
)
if SCRIPT_SPEC is None or SCRIPT_SPEC.loader is None:
    raise RuntimeError("fifteenth-tranche report builder cannot be loaded")
REPORT_SCRIPT = importlib.util.module_from_spec(SCRIPT_SPEC)
sys.modules[SCRIPT_SPEC.name] = REPORT_SCRIPT
SCRIPT_SPEC.loader.exec_module(REPORT_SCRIPT)

from cbds.executable_fixture_fifteenth_catalog import (  # noqa: E402
    build_fifteenth_tranche_fixture_catalog,
)
from cbds.hash_only_report_publication import (  # noqa: E402
    HashOnlyReportPublicationError,
)


REPORT = (
    ROOT / "reports" / "executable-fifteenth-tranche" / "manifest.json"
)
EXPECTED_REPORT_SHA256 = (
    "78e0add5e6eb3e694238caa9603109f4c810937e6948b17ae9106bb07885ff1b"
)
EXPECTED_REPORT_LENGTH = 56_276


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


class _CatalogProjection:
    def __init__(self, record: dict[str, object]) -> None:
        self._record = record

    def to_hash_only_record(self) -> dict[str, object]:
        return self._record


class FifteenthTrancheCatalogReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with mock.patch.object(
            subprocess,
            "run",
            side_effect=AssertionError("subprocess.run executed"),
        ), mock.patch.object(
            subprocess,
            "Popen",
            side_effect=AssertionError("subprocess.Popen executed"),
        ), mock.patch.object(
            os,
            "system",
            side_effect=AssertionError("os.system executed"),
        ), mock.patch.object(
            os,
            "popen",
            side_effect=AssertionError("os.popen executed"),
        ):
            cls.catalog = build_fifteenth_tranche_fixture_catalog()
        cls.record = cls.catalog.to_hash_only_record()
        cls.payload = _canonical_bytes(cls.record)

    def test_builder_serializes_only_central_bounded_projection(self) -> None:
        with mock.patch.object(
            REPORT_SCRIPT,
            "build_fifteenth_tranche_fixture_catalog",
            return_value=self.catalog,
        ) as central_builder:
            first = (
                REPORT_SCRIPT.canonical_fifteenth_tranche_catalog_bytes()
            )
            second = (
                REPORT_SCRIPT.canonical_fifteenth_tranche_catalog_bytes()
            )
        self.assertEqual(central_builder.call_count, 2)
        self.assertEqual(first, self.payload)
        self.assertEqual(second, self.payload)
        self.assertLessEqual(
            len(first),
            REPORT_SCRIPT.FIFTEENTH_TRANCHE_REPORT_MAXIMUM_BYTES,
        )
        parsed = json.loads(
            first.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"nonfinite JSON constant: {value}")
            ),
        )
        self.assertEqual(parsed, self.record)
        self.assertEqual(_canonical_bytes(parsed), first)
        self.assertEqual(len(first), EXPECTED_REPORT_LENGTH)
        self.assertEqual(sha256(first).hexdigest(), EXPECTED_REPORT_SHA256)

    def test_projection_is_hash_only_public_and_nonauthorizing(self) -> None:
        self.assertFalse(_contains_bytes(self.record))
        encoded = self.payload.decode("utf-8", errors="strict")
        self.assertEqual(
            self.record["record_type"],
            "cbds.executable-fixture-fifteenth-tranche-catalog",
        )
        self.assertEqual(self.record["added_task_count"], 20)
        self.assertEqual(self.record["cumulative_task_count"], 480)
        self.assertEqual(self.record["added_fixture_count"], 100)
        self.assertEqual(self.record["cumulative_fixture_count"], 2_400)
        self.assertEqual(len(self.record["added_tasks"]), 20)
        self.assertEqual(len(self.record["added_fixtures"]), 100)
        self.assertEqual(
            self.record["catalog_sha256"], self.catalog.catalog_sha256
        )
        generators = self.record["family_generators"]
        self.assertEqual(len(generators), 1)
        self.assertEqual(
            generators[0]["family_id"],
            "process-lifecycle-delta",
        )
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

    def test_authority_or_size_drift_fails_before_publication(self) -> None:
        forged = dict(self.record)
        forged["candidate_execution_authorized"] = True
        with mock.patch.object(
            REPORT_SCRIPT,
            "build_fifteenth_tranche_fixture_catalog",
            return_value=_CatalogProjection(forged),
        ), self.assertRaisesRegex(
            HashOnlyReportPublicationError, "authority boundary"
        ):
            REPORT_SCRIPT.canonical_fifteenth_tranche_catalog_bytes()

        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "manifest.json"
            oversized = b"x" * (
                REPORT_SCRIPT.FIFTEENTH_TRANCHE_REPORT_MAXIMUM_BYTES + 1
            )
            with self.assertRaisesRegex(
                HashOnlyReportPublicationError, "fixed byte bound"
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(report, oversized)
            self.assertFalse(report.exists())

    def test_publication_is_idempotent_exact_and_no_replace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "nested" / "manifest.json"
            REPORT_SCRIPT.atomic_publish_noreplace(report, self.payload)
            first = report.lstat()
            self.assertTrue(stat.S_ISREG(first.st_mode))
            self.assertEqual(stat.S_IMODE(first.st_mode), 0o644)
            self.assertEqual(first.st_nlink, 1)
            self.assertEqual(
                stat.S_IMODE(report.parent.lstat().st_mode),
                0o755,
            )
            self.assertEqual(report.read_bytes(), self.payload)
            self.assertEqual(
                list(report.parent.glob(".cbds-fifteenth-*.tmp")),
                [],
            )
            REPORT_SCRIPT.atomic_publish_noreplace(report, self.payload)
            second = report.lstat()
            self.assertEqual(
                (second.st_dev, second.st_ino),
                (first.st_dev, first.st_ino),
            )
            with self.assertRaisesRegex(
                HashOnlyReportPublicationError, "differs"
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(
                    report, self.payload + b"different"
                )
            self.assertEqual(report.read_bytes(), self.payload)

    def test_check_mode_and_committed_artifact_are_exact(self) -> None:
        self.assertEqual(REPORT.read_bytes(), self.payload)
        report_stat = REPORT.lstat()
        self.assertTrue(stat.S_ISREG(report_stat.st_mode))
        self.assertEqual(stat.S_IMODE(report_stat.st_mode), 0o644)
        self.assertEqual(report_stat.st_nlink, 1)
        self.assertEqual(
            stat.S_IMODE(REPORT.parent.lstat().st_mode),
            0o755,
        )
        with mock.patch.object(
            REPORT_SCRIPT,
            "canonical_fifteenth_tranche_catalog_bytes",
            return_value=self.payload,
        ) as canonical:
            self.assertEqual(
                REPORT_SCRIPT.main(
                    ["--output", os.fspath(REPORT), "--check"]
                ),
                0,
            )
            with tempfile.TemporaryDirectory() as temporary:
                absent = Path(temporary) / "absent.json"
                with self.assertRaisesRegex(SystemExit, "does not exist"):
                    REPORT_SCRIPT.main(
                        ["--output", os.fspath(absent), "--check"]
                    )
        self.assertEqual(
            canonical.call_count,
            2,
        )

    def test_script_delegates_to_shared_hardened_primitives(self) -> None:
        path = Path("/tmp/cbds-fifteenth-report-delegation.json")
        with mock.patch.object(
            REPORT_SCRIPT,
            "_shared_atomic_publish_noreplace",
        ) as publisher:
            REPORT_SCRIPT.atomic_publish_noreplace(path, b"{}\n")
        publisher.assert_called_once_with(
            path,
            b"{}\n",
            REPORT_SCRIPT.FIFTEENTH_TRANCHE_TEMPORARY_PREFIX,
        )
        with mock.patch.object(
            REPORT_SCRIPT,
            "_shared_read_existing_regular",
            return_value=b"{}\n",
        ) as reader:
            self.assertEqual(
                REPORT_SCRIPT.read_existing_report(path), b"{}\n"
            )
        reader.assert_called_once_with(
            path,
            REPORT_SCRIPT.FIFTEENTH_TRANCHE_REPORT_MAXIMUM_BYTES,
        )


if __name__ == "__main__":
    unittest.main()
