from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cbds.cli import main
from cbds.manifests import atomic_write_json
from cbds.training_corpus import prepare_training_corpus
from tests.test_token_schedule import TinyTokenizer, corpus_config, schedule_config


def run_cli(arguments: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = main(arguments)
    return status, stdout.getvalue(), stderr.getvalue()


class TokenScheduleCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        with (self.source / "train.csv").open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle, lineterminator="\n")
            writer.writerow(["instruction", "bash"])
            writer.writerow(["List files", "find . -type f"])
            writer.writerow(["Print directory", "pwd"])
            writer.writerow(["Count lines", "wc -l -- input.txt"])
        (self.source / "README.md").write_text("---\nlicense: mit\n---\n", encoding="utf-8")
        self.corpus = self.root / "corpus"
        corpus_summary = prepare_training_corpus(
            corpus_config(self.source), source_root=self.source, output_dir=self.corpus
        )
        self.tokenizer = self.root / "tokenizer"
        self.tokenizer.mkdir()
        (self.tokenizer / "config.json").write_text(
            json.dumps({"model_type": "tiny", "vocab_size": 32, "tie_word_embeddings": True}),
            encoding="utf-8",
        )
        (self.tokenizer / "tokenizer_config.json").write_text(
            json.dumps({"tokenizer_class": "TinyTokenizer"}), encoding="utf-8"
        )
        (self.tokenizer / "tokenizer.json").write_text(
            json.dumps({"version": "test"}), encoding="utf-8"
        )
        self.config = self.root / "schedule-config.json"
        atomic_write_json(self.config, schedule_config(corpus_summary))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @patch("cbds.token_schedule.load_local_tokenizer", return_value=TinyTokenizer())
    def test_prepare_and_verify_reconstruct_exact_schedule(self, _loader: object) -> None:
        schedule = self.root / "schedule"
        summary = self.root / "schedule-summary.json"
        status, stdout, stderr = run_cli(
            [
                "prepare-token-schedule",
                "--config", str(self.config),
                "--corpus-dir", str(self.corpus),
                "--corpus-source-root", str(self.source),
                "--tokenizer-root", str(self.tokenizer),
                "--model-embedding-rows", "32",
                "--output-dir", str(schedule),
                "--summary", str(summary),
            ]
        )
        self.assertEqual(status, 0, stderr)
        self.assertEqual(stdout, "")
        prepared = json.loads(summary.read_text(encoding="utf-8"))
        self.assertFalse(prepared["training_executed"])
        self.assertFalse(prepared["claim_authorized"])

        status, stdout, stderr = run_cli(
            [
                "verify-token-schedule",
                "--schedule-dir", str(schedule),
                "--corpus-dir", str(self.corpus),
                "--corpus-source-root", str(self.source),
                "--tokenizer-root", str(self.tokenizer),
                "--model-embedding-rows", "32",
                "--expected-schedule-sha256", prepared["schedule_sha256"],
                "--expected-manifest-sha256", prepared["manifest_sha256"],
            ]
        )
        self.assertEqual(status, 0, stderr)
        verified = json.loads(stdout)
        self.assertTrue(verified["valid"])
        self.assertEqual(verified["schedule_sha256"], prepared["schedule_sha256"])
        self.assertFalse(verified["claim_authorized"])

    @patch("cbds.token_schedule.load_local_tokenizer", return_value=TinyTokenizer())
    def test_outputs_cannot_mutate_any_authenticated_input(self, _loader: object) -> None:
        status, _, stderr = run_cli(
            [
                "prepare-token-schedule",
                "--config", str(self.config),
                "--corpus-dir", str(self.corpus),
                "--corpus-source-root", str(self.source),
                "--tokenizer-root", str(self.tokenizer),
                "--model-embedding-rows", "32",
                "--output-dir", str(self.corpus / "schedule"),
            ]
        )
        self.assertEqual(status, 2)
        self.assertIn("outside --corpus-dir", stderr)


if __name__ == "__main__":
    unittest.main()
