from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.bashbench_audit import (  # noqa: E402
    BashBenchAuditError,
    compute_bashbench_audit_sha256,
    validate_bashbench_audit_report,
)


REPORT = ROOT / "reports" / "bashbench-release-audit" / "manifest.json"


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate key: {key}")
        value[key] = item
    return value


class BashBenchReleaseAuditReportTests(unittest.TestCase):
    def test_checked_report_is_authenticated_and_permanently_nonauthorizing(self) -> None:
        report = json.loads(
            REPORT.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite value: {value}")
            ),
        )
        self.assertEqual(
            validate_bashbench_audit_report(
                report,
                require_authenticated_projection=True,
            ),
            report,
        )
        self.assertEqual(
            report["audit_sha256"],
            "9ba34477e981b581ba15165fb304a11a89476d5fc7c41417b254786a7a64dc65",
        )
        self.assertIs(
            report["member_projection"]["all_members_match_expected_release_v1"],
            True,
        )
        self.assertEqual(
            report["member_projection"]["selected_member_set_sha256"],
            "752f138c9e389d63818295a5f6b553e213f602d92755f1c92bc58ec1d4ee8ccb",
        )
        self.assertEqual(
            {item["code"] for item in report["findings"]},
            {
                "released_candidate_handoff_not_proven",
                "released_counts_and_alignment_disagree",
                "released_execute_path_is_direct_subprocess",
            },
        )
        self.assertEqual(
            report["decision"]["status"],
            "diagnostic_only_released_harness_rejected",
        )
        for field in (
            "benchmark_eligible",
            "candidate_execution_authorized",
            "model_selection_authorized",
            "claim_authorized",
        ):
            self.assertIs(report["decision"][field], False)

    def test_release_counts_freeze_the_identity_mismatch_evidence(self) -> None:
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        command = report["released_data"]["command"]
        script = report["released_data"]["script"]

        self.assertEqual(
            (
                command["alignment"]["evaluation_records"],
                command["alignment"]["test_records"],
                command["alignment"]["evaluation_prompt_duplicates"]["unique_values"],
                command["tests"]["test_case_presence"]["present_nonempty"],
            ),
            (927, 927, 717, 773),
        )
        self.assertEqual(
            (
                script["alignment"]["evaluation_records"],
                script["alignment"]["test_records"],
                script["alignment"]["index_aligned_prompt_matches"],
                script["alignment"]["unique_prompt_intersection"],
                script["tests"]["is_safe_to_execute_values"],
            ),
            (179, 154, 2, 40, {"false": 114, "true": 40}),
        )
        self.assertIs(command["alignment"]["one_to_one_index_identity"], False)
        self.assertIs(script["alignment"]["one_to_one_index_identity"], False)
        self.assertEqual(
            report["released_harness"]["candidate_handoff"],
            {
                "both_harnesses_launch_only_bash_test_path": True,
                "candidate_handoff_proven": False,
                "harness_candidate_arguments_after_test_path": 0,
                "literal_solution_sh_references_across_test_scripts": 0,
            },
        )

    def test_rehashed_critical_release_evidence_tamper_is_rejected(self) -> None:
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        tampered = copy.deepcopy(report)
        tampered["released_data"]["command"]["alignment"][
            "index_aligned_prompt_matches"
        ] = 927
        tampered["audit_sha256"] = compute_bashbench_audit_sha256(tampered)
        with self.assertRaisesRegex(BashBenchAuditError, "task/count evidence"):
            validate_bashbench_audit_report(
                tampered,
                require_authenticated_projection=True,
            )


if __name__ == "__main__":
    unittest.main()
