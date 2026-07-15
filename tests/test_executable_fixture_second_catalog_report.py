from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_fixture_second_catalog import (  # noqa: E402
    build_second_tranche_fixture_catalog,
)


REPORT = ROOT / "reports" / "executable-second-tranche" / "manifest.json"
REPORT_SHA256 = "fe3ca14f000aca9a2945cba4a27acfeda086f0786ab1e52230f572d17977553f"
REGISTRY_SHA256 = "27e4721036c4870fec463e880cb3a36fcd72ebe530368cb45179f600ee694ab4"
CUMULATIVE_SUITE_SHA256 = (
    "0020c1e5c7907d979d7fa97dead79f199fff59d97184c33fae81bc98df3ef8fb"
)
CATALOG_SHA256 = "e2ad6a3124491bc25410d40278400aeac9cd8791a9f08a530c823d5f14c09e18"


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


class SecondTrancheCatalogReportTests(unittest.TestCase):
    def test_checked_manifest_is_the_exact_frozen_hash_only_projection(self) -> None:
        payload = REPORT.read_bytes()
        self.assertEqual(sha256(payload).hexdigest(), REPORT_SHA256)
        observed = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"nonfinite JSON constant: {value}")
            ),
        )

        catalog = build_second_tranche_fixture_catalog()
        expected = catalog.to_hash_only_record()
        self.assertEqual(payload, _canonical_bytes(expected))
        self.assertEqual(observed, expected)
        self.assertEqual(
            catalog.registry.registry_sha256,
            REGISTRY_SHA256,
        )
        self.assertEqual(
            catalog.registry.cumulative_suite_sha256,
            CUMULATIVE_SUITE_SHA256,
        )
        self.assertEqual(catalog.catalog_sha256, CATALOG_SHA256)

    def test_manifest_has_only_hashes_counts_and_nonauthorizing_metadata(self) -> None:
        record = json.loads(REPORT.read_text(encoding="utf-8"))
        encoded = json.dumps(record, ensure_ascii=False, sort_keys=True)
        self.assertEqual(record["added_task_count"], 100)
        self.assertEqual(record["cumulative_task_count"], 200)
        self.assertEqual(record["added_fixture_count"], 500)
        self.assertEqual(record["cumulative_fixture_count"], 1_000)
        self.assertEqual(len(record["added_tasks"]), 100)
        self.assertEqual(len(record["added_fixtures"]), 500)
        for forbidden in (
            '"content"',
            '"inputs"',
            '"outputs"',
            '"prompt"',
            "input/",
            "output/",
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertIs(record["sealed"], False)
        self.assertIs(record["candidate_execution_authorized"], False)
        self.assertIs(record["model_selection_eligible"], False)
        self.assertIs(record["claim_authorized"], False)


if __name__ == "__main__":
    unittest.main()
