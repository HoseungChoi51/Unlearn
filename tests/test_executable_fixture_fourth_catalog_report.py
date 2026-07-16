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

SCRIPT_PATH = ROOT / "scripts" / "build_executable_fourth_tranche_catalog.py"
SCRIPT_SPEC = importlib.util.spec_from_file_location(
    "cbds_build_executable_fourth_tranche_catalog",
    SCRIPT_PATH,
)
if SCRIPT_SPEC is None or SCRIPT_SPEC.loader is None:
    raise RuntimeError("fourth-tranche report builder cannot be loaded")
REPORT_SCRIPT = importlib.util.module_from_spec(SCRIPT_SPEC)
sys.modules[SCRIPT_SPEC.name] = REPORT_SCRIPT
SCRIPT_SPEC.loader.exec_module(REPORT_SCRIPT)

from cbds.executable_fixture_fourth_catalog import (  # noqa: E402
    build_fourth_tranche_fixture_catalog,
)


REPORT = ROOT / "reports" / "executable-fourth-tranche" / "manifest.json"
EXPECTED_REGISTRY_SHA256 = (
    "3dc5512139361a275afaf0b57b94528961615f9b4eee22ee6c333cc7d8bf4ea5"
)
EXPECTED_CUMULATIVE_SUITE_SHA256 = (
    "668ab9c942888d568c80aaa27bee340ad8a10faf3493a6983bf068d79b134651"
)
EXPECTED_CATALOG_SHA256 = (
    "54ff2e17645edfc7887fc39b437340ffe8d736b83001d0265612271c2a3b1d46"
)

# Byte identity of the checked hash-only report.  This authenticates the
# published projection; it is not a human-review or execution authorization.
REPORT_SHA256 = (
    "a79ba062de86574e95ff60ff4fa8bc48b223c934b70d65ed832da5631359eebb"
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


class FourthTrancheCatalogReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = build_fourth_tranche_fixture_catalog()
        cls.record = cls.catalog.to_hash_only_record()
        cls.payload = _canonical_bytes(cls.record)

    def test_builder_serializes_only_the_central_canonical_projection(self) -> None:
        with mock.patch.object(
            REPORT_SCRIPT,
            "build_fourth_tranche_fixture_catalog",
            return_value=self.catalog,
        ) as central_builder:
            first = REPORT_SCRIPT.canonical_fourth_tranche_catalog_bytes()
            second = REPORT_SCRIPT.canonical_fourth_tranche_catalog_bytes()
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
            "cbds.executable-fixture-fourth-tranche-catalog",
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
        self.assertEqual(self.record["cumulative_task_count"], 260)
        self.assertEqual(self.record["added_fixture_count"], 100)
        self.assertEqual(self.record["cumulative_fixture_count"], 1_300)
        self.assertEqual(len(self.record["added_tasks"]), 20)
        self.assertEqual(len(self.record["added_fixtures"]), 100)
        self.assertEqual(
            self.record["family_generators"],
            [
                {
                    "family_id": "reproducible-ustar-pack",
                    "generator_version": "1.0.0",
                    "semantic_verifier_identity": (
                        "verify-reproducible-ustar-pack-v1"
                    ),
                    "output_maximum_bytes": 1_048_576,
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
            report = Path(temporary) / "nested" / "fourth-catalog.json"
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
                REPORT_SCRIPT.FourthTrancheCatalogPublicationError,
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
                REPORT_SCRIPT.FourthTrancheCatalogPublicationError,
                "Path and immutable bytes",
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(  # type: ignore[arg-type]
                    str(report), self.payload
                )
            with self.assertRaisesRegex(
                REPORT_SCRIPT.FourthTrancheCatalogPublicationError,
                "Path and immutable bytes",
            ):
                REPORT_SCRIPT.atomic_publish_noreplace(  # type: ignore[arg-type]
                    report, bytearray(self.payload)
                )
            self.assertFalse(report.exists())

    def test_cli_uses_central_projection_and_checks_caller_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            REPORT_SCRIPT,
            "canonical_fourth_tranche_catalog_bytes",
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
            "the frozen fourth-tranche manifest must be checked in",
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
