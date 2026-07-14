from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import unittest

from cbds.manifests import value_sha256


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "engineering-dense-sft-canary" / "manifest.json"


class EngineeringDenseSFTCanaryReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = json.loads(REPORT.read_text(encoding="utf-8"))

    def test_report_is_self_addressed_and_nonclaiming(self) -> None:
        unsigned = dict(self.report)
        declared = unsigned.pop("manifest_sha256")
        self.assertEqual(declared, value_sha256(unsigned))
        self.assertEqual(self.report["claim_scope"], "none")
        eligibility = self.report["eligibility"]
        for name in (
            "source_target_policy_accepted",
            "campaign_eligible",
            "model_selection_eligible",
            "benchmark_result",
            "research_claim_authorized",
        ):
            self.assertFalse(eligibility[name])
        self.assertTrue(self.report["measurements"]["selection_use_prohibited"])

    def test_code_sources_are_exactly_bound(self) -> None:
        for relative, expected in self.report["code_sources"].items():
            self.assertEqual(sha256((ROOT / relative).read_bytes()).hexdigest(), expected)

    def test_token_parameter_and_serialized_byte_accounting_reproduce(self) -> None:
        schedule = self.report["source_schedule"]
        self.assertEqual(
            schedule["target_visible_tokens"] + schedule["support_visible_tokens"],
            schedule["total_visible_tokens"],
        )
        source = self.report["source_model"]
        exported = self.report["export"]
        self.assertEqual(source["physical_parameters"], exported["physical_parameters"])
        self.assertEqual(exported["physical_parameters"], exported["stored_tensor_elements"])
        self.assertEqual(
            exported["physical_parameters"] * 2,
            exported["safetensors_payload_bytes"],
        )
        self.assertEqual(
            exported["checkpoint_serialized_bytes_excluding_completion"]
            + exported["completion_file_bytes"],
            exported["complete_artifact_serialized_bytes"],
        )

    def test_verification_is_complete_and_record_is_portable(self) -> None:
        self.assertTrue(all(self.report["verification"].values()))
        self.assertFalse(self.report["runtime"]["os_socket_isolation_provided"])
        self.assertFalse(self.report["measurements"]["trajectory_determinism_guaranteed"])
        payload = REPORT.read_text(encoding="utf-8")
        self.assertNotIn("/home/", payload)
        self.assertNotIn("/tmp/", payload)
        self.assertNotIn("artifacts/", payload)


if __name__ == "__main__":
    unittest.main()
