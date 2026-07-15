from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_fixture_catalog import (  # noqa: E402
    build_first_tranche_fixture_catalog,
)
from cbds.executable_static_registry import (  # noqa: E402
    build_public_method_development_registry,
)


REPORT = ROOT / "reports" / "executable-first-tranche" / "manifest.json"
REPORT_SHA256 = "de290d087979b3db8ba22f61916a3041c49036ec4d638020411d4539250880b6"
REGISTRY_SHA256 = "ada6043b345e48f69ad602581030aab1bafcb3ff9dc453f9d02342faaf6a7f9a"
SUITE_SHA256 = "eb64bb4cdb60ab8e0e228f688cf54810fae2ef56768e8b34ac039bdc1aec42ae"
CATALOG_SHA256 = "1fc71f89830739a53b69d771b7d0bd6a79a4d78ff698b1c1c2258211e7776c99"


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


class FirstTrancheCatalogReportTests(unittest.TestCase):
    def test_checked_manifest_is_an_exact_fresh_hash_only_rebuild(self) -> None:
        payload = REPORT.read_bytes()
        self.assertEqual(sha256(payload).hexdigest(), REPORT_SHA256)
        observed = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"nonfinite JSON constant: {value}")
            ),
        )

        registry = build_public_method_development_registry()
        catalog = build_first_tranche_fixture_catalog(registry)
        expected_record = catalog.to_hash_only_record()
        expected_payload = (
            json.dumps(
                expected_record,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                indent=2,
            )
            + "\n"
        ).encode("utf-8")
        self.assertEqual(payload, expected_payload)
        self.assertEqual(observed, expected_record)
        self.assertEqual(registry.registry_sha256, REGISTRY_SHA256)
        self.assertEqual(registry.suite_sha256, SUITE_SHA256)
        self.assertEqual(catalog.catalog_sha256, CATALOG_SHA256)

    def test_manifest_carries_no_fixture_or_oracle_bytes_and_no_authority(self) -> None:
        record = json.loads(REPORT.read_text(encoding="utf-8"))
        encoded = json.dumps(record, ensure_ascii=False, sort_keys=True)
        self.assertEqual(record["task_count"], 100)
        self.assertEqual(record["fixture_count"], 500)
        self.assertNotIn("content", encoded)
        self.assertNotIn("answer", encoded)
        self.assertNotIn("input/", encoded)
        self.assertNotIn("output/", encoded)
        self.assertIs(record["sealed"], False)
        self.assertIs(record["candidate_execution_authorized"], False)
        self.assertIs(record["model_selection_eligible"], False)
        self.assertIs(record["claim_authorized"], False)


if __name__ == "__main__":
    unittest.main()
