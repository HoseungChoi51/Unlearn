from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from cbds.cli import main
from cbds.training_corpus import prepare_training_corpus
from tests.test_training_source_audit import csv_payload, fixture_config


def run_cli(arguments: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = main(arguments)
    return status, stdout.getvalue(), stderr.getvalue()


class TrainingSourceAuditCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        rows = [
            ("list files", "find . -type f"),
            ("download", "curl https://example.invalid/archive"),
        ]
        payload = csv_payload(rows)
        card = b"fixture card; raw rows remain unverified\n"
        (self.source / "train.csv").write_bytes(payload)
        (self.source / "README.md").write_bytes(card)
        self.corpus = self.root / "corpus"
        self.corpus_summary = prepare_training_corpus(
            fixture_config(payload, card, len(rows)),
            source_root=self.source,
            output_dir=self.corpus,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_prepare_then_authenticated_raw_replay_verify(self) -> None:
        audit = self.root / "audit"
        summary = self.root / "summary.json"
        status, stdout, stderr = run_cli(
            [
                "prepare-training-source-audit",
                "--audit-id", "cli-source-audit",
                "--corpus-dir", str(self.corpus),
                "--source-root", str(self.source),
                "--expected-corpus-sha256", self.corpus_summary["corpus_sha256"],
                "--expected-corpus-manifest-sha256", self.corpus_summary["manifest_sha256"],
                "--output-dir", str(audit),
                "--summary", str(summary),
            ]
        )
        self.assertEqual(status, 0, stderr)
        self.assertEqual(stdout, "")
        prepared = json.loads(summary.read_text(encoding="utf-8"))
        self.assertFalse(prepared["training_eligible"])
        self.assertFalse(prepared["target_policy_accepted"])

        status, stdout, stderr = run_cli(
            [
                "verify-training-source-audit",
                "--audit-dir", str(audit),
                "--expected-audit-sha256", prepared["audit_sha256"],
                "--expected-audit-manifest-sha256", prepared["manifest_sha256"],
                "--raw-corpus-dir", str(self.corpus),
                "--raw-source-root", str(self.source),
                "--expected-corpus-sha256", self.corpus_summary["corpus_sha256"],
                "--expected-corpus-manifest-sha256", self.corpus_summary["manifest_sha256"],
            ]
        )
        self.assertEqual(status, 0, stderr)
        verified = json.loads(stdout)
        self.assertTrue(verified["authenticated"])
        self.assertTrue(verified["raw_source_reverified"])
        self.assertFalse(verified["claim_authorized"])

    def test_prepare_output_cannot_be_nested_in_raw_inputs(self) -> None:
        status, _, stderr = run_cli(
            [
                "prepare-training-source-audit",
                "--audit-id", "cli-source-audit",
                "--corpus-dir", str(self.corpus),
                "--source-root", str(self.source),
                "--expected-corpus-sha256", self.corpus_summary["corpus_sha256"],
                "--expected-corpus-manifest-sha256", self.corpus_summary["manifest_sha256"],
                "--output-dir", str(self.corpus / "audit"),
            ]
        )
        self.assertEqual(status, 2)
        self.assertIn("outside --corpus-dir", stderr)


if __name__ == "__main__":
    unittest.main()
