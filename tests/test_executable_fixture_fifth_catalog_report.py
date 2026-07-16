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

SCRIPT_PATH = ROOT / "scripts" / "build_executable_fifth_tranche_catalog.py"
SCRIPT_SPEC = importlib.util.spec_from_file_location(
    "cbds_build_executable_fifth_tranche_catalog",
    SCRIPT_PATH,
)
if SCRIPT_SPEC is None or SCRIPT_SPEC.loader is None:
    raise RuntimeError("fifth-tranche report builder cannot be loaded")
REPORT_SCRIPT = importlib.util.module_from_spec(SCRIPT_SPEC)
sys.modules[SCRIPT_SPEC.name] = REPORT_SCRIPT
SCRIPT_SPEC.loader.exec_module(REPORT_SCRIPT)

from cbds.executable_fixture_fifth_catalog import (  # noqa: E402
    build_fifth_tranche_fixture_catalog,
)


REPORT = ROOT / "reports" / "executable-fifth-tranche" / "manifest.json"
EXPECTED_REGISTRY_SHA256 = (
    "d562d462814b7fc6413e0e085d16f66def28157c1a6361adf28cd3d42eb5f88c"
)
EXPECTED_CUMULATIVE_SUITE_SHA256 = (
    "27ea8064a72453a4e7a4bc52b125a924139088cd1c20d417a867aa9ddda96e00"
)
EXPECTED_CATALOG_SHA256 = (
    "cb24e42fc27500fa5076224dfc195a6fe2a4b08752724f09ff944961aa7221db"
)

# Byte identity of the checked hash-only report.  This authenticates the
# published projection; it is not a human-review or execution authorization.
REPORT_SHA256 = (
    "80959058c764da72437bfa1bd01a2eb1c747a221ec1c06f59278c02b80e0ef48"
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


class FifthTrancheCatalogReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = build_fifth_tranche_fixture_catalog()
        cls.record = cls.catalog.to_hash_only_record()
        cls.payload = _canonical_bytes(cls.record)

    def test_builder_serializes_only_the_central_canonical_projection(self) -> None:
        with mock.patch.object(
            REPORT_SCRIPT,
            "build_fifth_tranche_fixture_catalog",
            return_value=self.catalog,
        ) as central_builder:
            first = REPORT_SCRIPT.canonical_fifth_tranche_catalog_bytes()
            second = REPORT_SCRIPT.canonical_fifth_tranche_catalog_bytes()
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

    def test_projection_binds_hashes_and_contains_no_sensitive_bytes(self) -> None:
        self.assertFalse(_contains_bytes(self.record))
        encoded = self.payload.decode("utf-8", errors="strict")
        self.assertEqual(
            self.record["record_type"],
            "cbds.executable-fixture-fifth-tranche-catalog",
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
        self.assertEqual(self.record["cumulative_task_count"], 280)
        self.assertEqual(self.record["added_fixture_count"], 100)
        self.assertEqual(self.record["cumulative_fixture_count"], 1_400)
        self.assertEqual(len(self.record["added_tasks"]), 20)
        self.assertEqual(len(self.record["added_fixtures"]), 100)
        self.assertEqual(
            self.record["family_generators"],
            [
                {
                    "family_id": "pipefail-atomic-report",
                    "generator_version": "1.0.0",
                    "semantic_verifier_identity": (
                        "verify-pipefail-atomic-report-v1"
                    ),
                    "output_maximum_bytes": 65_536,
                }
            ],
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

    def test_atomic_publication_is_idempotent_and_never_replaces(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "nested" / "fifth-catalog.json"
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
                REPORT_SCRIPT.FifthTrancheCatalogPublicationError,
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
                REPORT_SCRIPT.FifthTrancheCatalogPublicationError,
                "Path and immutable bytes",
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(  # type: ignore[arg-type]
                    str(report), self.payload
                )
            with self.assertRaisesRegex(
                REPORT_SCRIPT.FifthTrancheCatalogPublicationError,
                "Path and immutable bytes",
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(  # type: ignore[arg-type]
                    report, bytearray(self.payload)
                )
            self.assertFalse(report.exists())

    def test_cli_uses_central_projection_and_checks_caller_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            REPORT_SCRIPT,
            "canonical_fifth_tranche_catalog_bytes",
            return_value=self.payload,
        ) as central_projection:
            report = Path(temporary) / "caller" / "manifest.json"
            self.assertEqual(REPORT_SCRIPT.main(["--output", str(report)]), 0)
            self.assertEqual(
                REPORT_SCRIPT.main(["--output", str(report), "--check"]), 0
            )
            self.assertEqual(report.read_bytes(), self.payload)

            missing = Path(temporary) / "missing.json"
            with self.assertRaisesRegex(SystemExit, "does not exist"):
                REPORT_SCRIPT.main(["--output", str(missing), "--check"])
            report.write_bytes(b"different\n")
            with self.assertRaisesRegex(SystemExit, "differs"):
                REPORT_SCRIPT.main(["--output", str(report)])
            self.assertEqual(report.read_bytes(), b"different\n")
        self.assertEqual(central_projection.call_count, 4)

    def test_checked_manifest_has_frozen_byte_identity(self) -> None:
        self.assertTrue(
            REPORT.is_file(),
            "the frozen fifth-tranche manifest must be checked in",
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
