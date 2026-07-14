from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from cbds.cli import main
from cbds.manifests import atomic_write_json
from tests.test_training_corpus import csv_payload, fixture_config


def run_cli(arguments: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = main(arguments)
    return status, stdout.getvalue(), stderr.getvalue()


class TrainingCorpusCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.payload = csv_payload([("list files", "ls"), ("show path", "pwd")])
        self.card = b"license: mit\nfixture card\n"
        (self.source / "train.csv").write_bytes(self.payload)
        (self.source / "README.md").write_bytes(self.card)
        self.config = self.root / "config.json"
        atomic_write_json(
            self.config,
            fixture_config(self.payload, self.card, rows=2, unique=2),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_prepare_and_verify_emit_content_only_summaries(self) -> None:
        corpus = self.root / "corpus"
        summary = self.root / "summary.json"
        status, stdout, stderr = run_cli(
            [
                "prepare-training-corpus",
                "--config",
                str(self.config),
                "--source-root",
                str(self.source),
                "--output-dir",
                str(corpus),
                "--summary",
                str(summary),
            ]
        )
        self.assertEqual(status, 0, stderr)
        self.assertEqual(stdout, "")
        prepared = json.loads(summary.read_text(encoding="utf-8"))
        self.assertFalse(prepared["claim_authorized"])
        self.assertNotIn("list files", summary.read_text(encoding="utf-8"))

        status, stdout, stderr = run_cli(
            [
                "verify-training-corpus",
                "--corpus-dir",
                str(corpus),
                "--expected-corpus-sha256",
                prepared["corpus_sha256"],
                "--expected-manifest-sha256",
                prepared["manifest_sha256"],
                "--require-authenticated",
            ]
        )
        self.assertEqual(status, 0, stderr)
        verified = json.loads(stdout)
        self.assertTrue(verified["valid"])
        self.assertTrue(verified["authenticated"])
        self.assertFalse(verified["claim_authorized"])
        self.assertNotIn("list files", stdout)

    def test_outputs_cannot_mutate_source_or_corpus(self) -> None:
        status, _, stderr = run_cli(
            [
                "prepare-training-corpus",
                "--config",
                str(self.config),
                "--source-root",
                str(self.source),
                "--output-dir",
                str(self.source / "generated"),
            ]
        )
        self.assertEqual(status, 2)
        self.assertIn("outside --source-root", json.loads(stderr)["message"])

        corpus = self.root / "corpus"
        prepared, _, error = run_cli(
            [
                "prepare-training-corpus",
                "--config",
                str(self.config),
                "--source-root",
                str(self.source),
                "--output-dir",
                str(corpus),
            ]
        )
        self.assertEqual(prepared, 0, error)
        manifest_before = (corpus / "manifest.json").read_bytes()
        status, _, stderr = run_cli(
            [
                "verify-training-corpus",
                "--corpus-dir",
                str(corpus),
                "--output",
                str(corpus / "verification.json"),
            ]
        )
        self.assertEqual(status, 2)
        self.assertIn("outside --corpus-dir", json.loads(stderr)["message"])
        self.assertEqual((corpus / "manifest.json").read_bytes(), manifest_before)
        self.assertFalse((corpus / "verification.json").exists())


if __name__ == "__main__":
    unittest.main()
