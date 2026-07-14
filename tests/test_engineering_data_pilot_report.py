from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import unittest

from cbds.manifests import load_document, value_sha256
from cbds.token_schedule import token_schedule_config_sha256
from cbds.training_corpus import training_corpus_config_sha256


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "engineering-data-pilot" / "manifest.json"


class EngineeringDataPilotReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = json.loads(REPORT.read_text(encoding="utf-8"))

    def test_report_is_self_addressed_and_unconditionally_nonclaiming(self) -> None:
        unsigned = dict(self.report)
        declared = unsigned.pop("manifest_sha256")
        self.assertEqual(declared, value_sha256(unsigned))
        self.assertEqual(self.report["claim_scope"], "none")
        eligibility = self.report["eligibility"]
        self.assertTrue(eligibility["engineering_canary_only"])
        for name in (
            "research_training_authorized",
            "target_policy_accepted",
            "evaluation_executed",
            "model_selection_authorized",
            "research_claim_authorized",
        ):
            self.assertFalse(eligibility[name])

    def test_checked_in_inputs_and_code_are_exactly_bound(self) -> None:
        for relative, binding in self.report["checked_in_inputs"].items():
            path = ROOT / relative
            self.assertEqual(sha256(path.read_bytes()).hexdigest(), binding["file_sha256"])
            document = load_document(path)
            if path.name.startswith("training-corpus"):
                actual = training_corpus_config_sha256(document)
            else:
                actual = token_schedule_config_sha256(document)
            self.assertEqual(actual, binding["canonical_config_sha256"])
        for relative, expected in self.report["code_sources"].items():
            self.assertEqual(sha256((ROOT / relative).read_bytes()).hexdigest(), expected)

    def test_aggregate_accounting_is_internally_exact(self) -> None:
        corpus = self.report["raw_corpus"]
        self.assertEqual(
            corpus["target_records"] + corpus["support_records"],
            corpus["total_records"],
        )
        schedule = self.report["token_schedule"]
        self.assertEqual(
            schedule["target_visible_tokens"] + schedule["support_visible_tokens"],
            schedule["total_visible_tokens"],
        )
        self.assertEqual(
            schedule["total_visible_tokens"] + schedule["padding_tokens"],
            schedule["packed_token_slots"],
        )
        self.assertEqual(
            schedule["packed_sequences"] * schedule["sequence_length"],
            schedule["packed_token_slots"],
        )
        prefilter = self.report["source_prefilter"]
        self.assertEqual(
            prefilter["static_candidates"] + prefilter["rejected"],
            prefilter["source_records"],
        )
        self.assertEqual(
            prefilter["static_candidate_fraction"],
            {
                "numerator": prefilter["static_candidates"],
                "denominator": prefilter["source_records"],
            },
        )
        self.assertTrue(prefilter["authenticated"])
        for name in (
            "ast_parsed",
            "execution_verified",
            "training_eligible",
            "target_policy_accepted",
            "claim_authorized",
        ):
            self.assertFalse(prefilter[name])

    def test_report_is_portable_and_retains_no_training_text(self) -> None:
        payload = REPORT.read_text(encoding="utf-8")
        self.assertNotIn("/home/", payload)
        self.assertNotIn("/tmp/", payload)
        self.assertNotIn("target.jsonl", payload)
        self.assertNotIn("support.jsonl", payload)


if __name__ == "__main__":
    unittest.main()
