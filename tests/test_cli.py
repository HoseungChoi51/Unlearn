from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from cbds.cli import main
from cbds.manifests import atomic_write_json
from tests.test_manifests import valid_hardware_result


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_MANIFEST = ROOT / "examples" / "experiment-manifest.example.json"
PINNED_IMAGE = "example.invalid/cbds/runtime@sha256:" + "a" * 64


def run_cli(arguments: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = main(arguments)
    return status, stdout.getvalue(), stderr.getvalue()


class CliIntegrationTests(unittest.TestCase):
    def test_prepare_writes_the_smoke_dataset_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_dir = root / "dataset"
            summary = root / "summary.json"
            status, stdout, stderr = run_cli(
                [
                    "prepare",
                    "--config",
                    str(ROOT / "configs" / "benchmark-smoke.json"),
                    "--output-dir",
                    str(output_dir),
                    "--summary",
                    str(summary),
                ]
            )
            self.assertEqual(status, 0, stderr)
            self.assertEqual(stdout, "")
            document = json.loads(summary.read_text(encoding="utf-8"))
            self.assertEqual(document["total_records"], 29)
            self.assertEqual(len(document["files"]), 12)
            self.assertTrue((output_dir / "manifest.sha256").is_file())

    def test_evaluate_reports_frozen_extraction_and_syntax_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            response = Path(directory) / "response.txt"
            response.write_text("```bash\nprintf '%s\\n' ok\n```", encoding="utf-8")
            status, stdout, stderr = run_cli(
                ["evaluate", "--response", str(response)]
            )
            self.assertEqual(status, 0, stderr)
            document = json.loads(stdout)
            self.assertFalse(document["policy"]["executes_program"])
            self.assertEqual(document["policy"]["max_response_bytes"], 65536)
            self.assertEqual(document["parsed"]["status"], "ok")
            self.assertEqual(document["syntax"]["status"], "ok")
            self.assertEqual(document["parsed"]["code"], "printf '%s\\n' ok")

    def test_evaluate_hashes_and_limits_original_crlf_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            response = Path(directory) / "response.txt"
            payload = b"echo\r\nx\r\n"
            response.write_bytes(payload)
            status, stdout, stderr = run_cli(
                [
                    "evaluate",
                    "--response",
                    str(response),
                    "--max-bytes",
                    "7",
                ]
            )
            self.assertEqual(status, 0, stderr)
            document = json.loads(stdout)
            self.assertEqual(document["response_sha256"], sha256(payload).hexdigest())
            self.assertEqual(document["parsed"]["response_bytes"], len(payload))
            self.assertEqual(document["parsed"]["status"], "truncation")

    def test_evaluate_python_parser_exhaustion_returns_a_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            response = Path(directory) / "response.txt"
            response.write_text(
                "```python\n" + "-" * 50_000 + "1\n```", encoding="utf-8"
            )
            status, stdout, stderr = run_cli(
                ["evaluate", "--response", str(response)]
            )
            self.assertEqual(status, 0, stderr)
            document = json.loads(stdout)
            self.assertEqual(document["syntax"]["status"], "check_failure")
            self.assertIn("parser limits", document["syntax"]["detail"])

    def test_sandbox_command_is_stdin_only_and_never_executes(self) -> None:
        status, stdout, stderr = run_cli(
            [
                "sandbox-command",
                "--engine",
                "podman",
                "--image",
                PINNED_IMAGE,
                "--language",
                "python",
            ]
        )
        self.assertEqual(status, 0, stderr)
        document = json.loads(stdout)
        argv = document["argv"]
        self.assertEqual(argv[:2], ["podman", "run"])
        self.assertEqual(document["program_transport"], "stdin")
        self.assertFalse(document["executed"])
        self.assertIn("--network=none", argv)
        self.assertFalse(any(item in {"-v", "--volume", "--mount"} for item in argv))

    def test_stage_dry_run_is_validated_and_content_addressed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            first_status, _, first_error = run_cli(
                [
                    "train",
                    "--manifest",
                    str(EXAMPLE_MANIFEST),
                    "--output",
                    str(first),
                    "--dry-run",
                ]
            )
            second_status, _, second_error = run_cli(
                [
                    "train",
                    "--manifest",
                    str(EXAMPLE_MANIFEST),
                    "--output",
                    str(second),
                    "--dry-run",
                ]
            )
            self.assertEqual(first_status, 0, first_error)
            self.assertEqual(second_status, 0, second_error)
            first_document = json.loads(first.read_text(encoding="utf-8"))
            second_document = json.loads(second.read_text(encoding="utf-8"))
            self.assertEqual(
                first_document["validation_id"], second_document["validation_id"]
            )
            self.assertEqual(first_document["validation_status"], "valid")
            self.assertEqual(first_document["execution_status"], "not_executed")
            self.assertEqual(
                first_document["manifest_kind"], "completed_experiment_record"
            )
            self.assertEqual(len(first_document["manifest_sha256"]), 64)

    def test_prepare_rejects_configs_that_depend_on_hidden_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "partial.json"
            config.write_text('{"seed": 1}', encoding="utf-8")
            status, stdout, stderr = run_cli(
                [
                    "prepare",
                    "--config",
                    str(config),
                    "--output-dir",
                    str(root / "output"),
                ]
            )
            self.assertEqual(status, 2)
            self.assertEqual(stdout, "")
            self.assertFalse((root / "output").exists())
            self.assertIn("omits required explicit fields", json.loads(stderr)["message"])

    def test_unimplemented_training_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "plan.json"
            status, stdout, stderr = run_cli(
                [
                    "train",
                    "--manifest",
                    str(EXAMPLE_MANIFEST),
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(status, 2)
            self.assertEqual(stdout, "")
            self.assertFalse(output.exists())
            error = json.loads(stderr)
            self.assertEqual(error["error"], "CliError")
            self.assertIn("not implemented", error["message"])

    def test_hardware_commands_use_packaged_schema_outside_repo_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "result.json"
            merged = root / "merged.json"
            atomic_write_json(source, valid_hardware_result())
            previous = Path.cwd()
            try:
                os.chdir(root)
                validate_status, validate_stdout, validate_stderr = run_cli(
                    ["bench-hardware", "validate", str(source)]
                )
                merge_status, merge_stdout, merge_stderr = run_cli(
                    ["merge-results", str(source), "--output", str(merged)]
                )
            finally:
                os.chdir(previous)
            self.assertEqual(validate_status, 0, validate_stderr)
            self.assertTrue(json.loads(validate_stdout)["results"][0]["valid"])
            self.assertEqual(merge_status, 0, merge_stderr)
            self.assertEqual(merge_stdout, "")
            self.assertEqual(json.loads(merged.read_text())["result_count"], 1)


if __name__ == "__main__":
    unittest.main()
