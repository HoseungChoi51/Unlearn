from __future__ import annotations

from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

SCRIPT_PATH = ROOT / "scripts" / "build_executable_third_tranche_catalog.py"
SCRIPT_SPEC = importlib.util.spec_from_file_location(
    "cbds_build_executable_third_tranche_catalog",
    SCRIPT_PATH,
)
if SCRIPT_SPEC is None or SCRIPT_SPEC.loader is None:
    raise RuntimeError("third-tranche report builder cannot be loaded")
REPORT_SCRIPT = importlib.util.module_from_spec(SCRIPT_SPEC)
sys.modules[SCRIPT_SPEC.name] = REPORT_SCRIPT
SCRIPT_SPEC.loader.exec_module(REPORT_SCRIPT)

from cbds.executable_fixture_third_catalog import (  # noqa: E402
    build_third_tranche_fixture_catalog,
)


REPORT = ROOT / "reports" / "executable-third-tranche" / "manifest.json"

# Byte identity of the checked hash-only report.  This authenticates the
# published projection; it is not a human-review or execution authorization.
REPORT_SHA256 = (
    "58e7e299142bd2c9681f9940f8277489115fa76350ffa53fb984bed81ceac862"
)


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


class ThirdTrancheCatalogReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = build_third_tranche_fixture_catalog()
        cls.record = cls.catalog.to_hash_only_record()
        cls.payload = _canonical_bytes(cls.record)

    def test_builder_serializes_only_the_central_canonical_projection(self) -> None:
        with mock.patch.object(
            REPORT_SCRIPT,
            "build_third_tranche_fixture_catalog",
            return_value=self.catalog,
        ) as central_builder:
            first = REPORT_SCRIPT.canonical_third_tranche_catalog_bytes()
            second = REPORT_SCRIPT.canonical_third_tranche_catalog_bytes()
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

    def test_projection_is_hash_only_and_nonauthorizing(self) -> None:
        self.assertFalse(_contains_bytes(self.record))
        encoded = self.payload.decode("utf-8", errors="strict")
        self.assertEqual(
            self.record["record_type"],
            "cbds.executable-fixture-third-tranche-catalog",
        )
        self.assertEqual(self.record["added_task_count"], 40)
        self.assertEqual(self.record["cumulative_task_count"], 240)
        self.assertEqual(self.record["added_fixture_count"], 200)
        self.assertEqual(self.record["cumulative_fixture_count"], 1_200)
        self.assertEqual(len(self.record["added_tasks"]), 40)
        self.assertEqual(len(self.record["added_fixtures"]), 200)
        for forbidden in (
            '"content"',
            '"inputs"',
            '"outputs"',
            '"prompt"',
            '"answer"',
            "input/",
            "output/",
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertIs(self.record["public_method_development"], True)
        self.assertIs(self.record["sealed"], False)
        self.assertIs(self.record["independent_human_review_attested"], False)
        self.assertIs(self.record["candidate_execution_authorized"], False)
        self.assertIs(self.record["model_selection_eligible"], False)
        self.assertIs(self.record["claim_authorized"], False)

    def test_atomic_publication_is_idempotent_and_never_replaces(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "nested" / "third-catalog.json"
            REPORT_SCRIPT.atomic_publish_noreplace(report, self.payload)
            first_stat = report.stat()
            self.assertEqual(report.read_bytes(), self.payload)
            self.assertEqual(stat.S_IMODE(first_stat.st_mode), 0o644)
            self.assertEqual(
                list(report.parent.glob(f".{report.name}.*.tmp")), []
            )

            REPORT_SCRIPT.atomic_publish_noreplace(report, self.payload)
            self.assertEqual(report.stat().st_ino, first_stat.st_ino)
            with self.assertRaisesRegex(
                REPORT_SCRIPT.ThirdTrancheCatalogPublicationError,
                "differs",
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(
                    report, self.payload + b"different"
                )
            self.assertEqual(report.read_bytes(), self.payload)
            self.assertEqual(
                list(report.parent.glob(f".{report.name}.*.tmp")), []
            )

    def test_publication_rejects_nonexact_payloads_and_invalid_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "manifest.json"
            with self.assertRaisesRegex(
                REPORT_SCRIPT.ThirdTrancheCatalogPublicationError,
                "Path and immutable bytes",
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(  # type: ignore[arg-type]
                    str(report), self.payload
                )
            with self.assertRaisesRegex(
                REPORT_SCRIPT.ThirdTrancheCatalogPublicationError,
                "Path and immutable bytes",
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(  # type: ignore[arg-type]
                    report, bytearray(self.payload)
                )
            self.assertFalse(report.exists())

    def test_cli_uses_central_projection_and_checks_caller_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            REPORT_SCRIPT,
            "canonical_third_tranche_catalog_bytes",
            return_value=self.payload,
        ) as central_projection:
            report = Path(temporary) / "caller" / "manifest.json"
            self.assertEqual(REPORT_SCRIPT.main(["--output", str(report)]), 0)
            self.assertEqual(
                REPORT_SCRIPT.main(["--output", str(report), "--check"]),
                0,
            )
            self.assertEqual(report.read_bytes(), self.payload)

            missing = Path(temporary) / "missing.json"
            with self.assertRaisesRegex(SystemExit, "does not exist"):
                REPORT_SCRIPT.main(
                    ["--output", str(missing), "--check"]
                )
            report.write_bytes(b"different\n")
            with self.assertRaisesRegex(SystemExit, "differs"):
                REPORT_SCRIPT.main(["--output", str(report)])
            self.assertEqual(report.read_bytes(), b"different\n")
        self.assertEqual(central_projection.call_count, 4)

    def test_checked_manifest_has_frozen_byte_identity_when_published(self) -> None:
        self.assertTrue(
            REPORT.is_file(),
            "the frozen third-tranche manifest must be checked in",
        )
        self.assertFalse(REPORT.is_symlink())
        payload = REPORT.read_bytes()
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
