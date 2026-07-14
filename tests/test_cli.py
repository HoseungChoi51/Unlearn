from __future__ import annotations

import copy
from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cbds.cli import main
from cbds.evaluation_specs import section_policy_sha256
from cbds.manifests import atomic_write_json, value_sha256
from cbds.model_runtime import compute_runtime_report_sha256
from tests.test_manifests import (
    hardware_result_for_completed_record,
    valid_hardware_result,
)
from tests.test_run_specs import valid_compress_spec


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_MANIFEST = ROOT / "examples" / "experiment-manifest.example.json"
EXAMPLE_RUN_SPEC = ROOT / "examples" / "run-spec.example.json"
EXAMPLE_EVALUATION_SPEC = ROOT / "examples" / "evaluation-spec.example.json"
CAMPAIGN_POLICY = ROOT / "configs" / "campaign-policy.json"
PINNED_IMAGE = "example.invalid/cbds/runtime@sha256:" + "a" * 64


def run_cli(arguments: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = main(arguments)
    return status, stdout.getvalue(), stderr.getvalue()


class CliIntegrationTests(unittest.TestCase):
    def test_validate_run_spec_supports_noncampaign_diagnostic_specs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_spec = root / "pure-ptq.json"
            output = root / "validation.json"
            atomic_write_json(run_spec, valid_compress_spec())
            status, stdout, stderr = run_cli(
                [
                    "validate-run-spec",
                    "--run-spec",
                    str(run_spec),
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(status, 0, stderr)
            self.assertEqual(stdout, "")
            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(document["valid"])
            self.assertFalse(document["campaign_qualified"])
            self.assertEqual(document["stage"], "compress")
            self.assertEqual(document["execution_status"], "not_executed")
            self.assertEqual(
                document["validation_scope"],
                "run_spec_schema_and_semantics_only",
            )

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

            verify_status, verify_stdout, verify_stderr = run_cli(
                ["verify-benchmark", "--dataset-dir", str(output_dir)]
            )
            self.assertEqual(verify_status, 0, verify_stderr)
            verification = json.loads(verify_stdout)
            self.assertTrue(verification["valid"])
            self.assertEqual(verification["total_records"], 29)
            self.assertTrue(
                verification["verification_policy"]["reject_extra_files"]
            )

    def test_evaluate_reports_frozen_extraction_and_syntax_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            response = Path(directory) / "response.txt"
            response.write_text("```bash\nprintf '%s\\n' ok\n```", encoding="utf-8")
            status, stdout, stderr = run_cli(
                [
                    "evaluate",
                    "--response",
                    str(response),
                    "--evaluation-spec",
                    str(EXAMPLE_EVALUATION_SPEC),
                ]
            )
            self.assertEqual(status, 0, stderr)
            document = json.loads(stdout)
            self.assertFalse(document["policy"]["executes_program"])
            self.assertFalse(document["policy"]["scored_evaluation_eligible"])
            self.assertFalse(document["policy"]["retains_plaintext"])
            self.assertEqual(document["policy"]["max_response_bytes"], 65536)
            self.assertEqual(document["policy"]["python_feature_version"], [3, 11])
            self.assertEqual(
                document["policy"]["syntax_environment"], "host_diagnostic_only"
            )
            self.assertEqual(
                len(
                    document["policy"]["bash_checker_identity"][
                        "executable_sha256"
                    ]
                ),
                64,
            )
            self.assertEqual(document["parsed"]["status"], "ok")
            self.assertEqual(document["syntax"]["status"], "ok")
            self.assertNotIn("code", document["parsed"])
            self.assertEqual(
                document["parsed"]["code_sha256"],
                sha256(b"printf '%s\\n' ok").hexdigest(),
            )
            self.assertEqual(len(document["evaluation_spec_sha256"]), 64)

    def test_evaluate_hashes_and_limits_original_crlf_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            response = root / "response.txt"
            payload = b"echo\r\nx\r\n"
            response.write_bytes(payload)
            spec = json.loads(EXAMPLE_EVALUATION_SPEC.read_text(encoding="utf-8"))
            spec["limits"]["maximum_response_bytes"] = 7
            spec_path = root / "evaluation-spec.json"
            atomic_write_json(spec_path, spec)
            status, stdout, stderr = run_cli(
                [
                    "evaluate",
                    "--response",
                    str(response),
                    "--evaluation-spec",
                    str(spec_path),
                ]
            )
            self.assertEqual(status, 0, stderr)
            document = json.loads(stdout)
            self.assertEqual(document["response_sha256"], sha256(payload).hexdigest())
            self.assertEqual(document["parsed"]["response_bytes"], len(payload))
            self.assertEqual(document["parsed"]["status"], "truncation")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO support is unavailable")
    def test_evaluate_rejects_fifo_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "response.fifo"
            os.mkfifo(fifo)
            status, stdout, stderr = run_cli(
                [
                    "evaluate",
                    "--response",
                    str(fifo),
                    "--evaluation-spec",
                    str(EXAMPLE_EVALUATION_SPEC),
                ]
            )
            self.assertEqual(status, 2)
            self.assertEqual(stdout, "")
            self.assertIn("regular file", json.loads(stderr)["message"])

    def test_evaluate_python_parser_exhaustion_returns_a_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            response = root / "response.txt"
            response.write_text(
                "```python\n" + "-" * 50_000 + "1\n```", encoding="utf-8"
            )
            spec = json.loads(EXAMPLE_EVALUATION_SPEC.read_text(encoding="utf-8"))
            spec["parser"]["program_language"] = "python"
            spec["parser"]["allowed_languages"] = ["python"]
            spec["parser"]["policy_sha256"] = section_policy_sha256(spec["parser"])
            allowed = sorted(spec["tool_policy"]["allowed_executables"] + ["python3"])
            spec["tool_policy"].update(
                {
                    "track": "python_permitted",
                    "allowed_executables": allowed,
                    "allowlist_sha256": value_sha256(allowed),
                    "python_allowed": True,
                }
            )
            spec["tool_policy"]["policy_sha256"] = section_policy_sha256(
                spec["tool_policy"]
            )
            spec_path = root / "evaluation-spec.json"
            atomic_write_json(spec_path, spec)
            status, stdout, stderr = run_cli(
                [
                    "evaluate",
                    "--response",
                    str(response),
                    "--evaluation-spec",
                    str(spec_path),
                ]
            )
            self.assertEqual(status, 0, stderr)
            document = json.loads(stdout)
            self.assertEqual(document["syntax"]["status"], "check_failure")
            self.assertNotIn("detail", document["syntax"])
            self.assertRegex(document["syntax"]["detail_sha256"], r"^[0-9a-f]{64}$")

    def test_evaluation_spec_validation_is_content_addressed_and_non_overwriting(self) -> None:
        status, stdout, stderr = run_cli(
            [
                "validate-evaluation-spec",
                "--evaluation-spec",
                str(EXAMPLE_EVALUATION_SPEC),
            ]
        )
        self.assertEqual(status, 0, stderr)
        document = json.loads(stdout)
        self.assertTrue(document["valid"])
        self.assertFalse(document["sealed"])
        self.assertEqual(document["split_role"], "method_development")
        self.assertRegex(document["evaluation_spec_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            document["artifact_binding_status"],
            "unbound_prospective_hashes_only",
        )
        self.assertIsNone(document["completed_experiment_record_sha256"])

        bound_status, bound_stdout, bound_stderr = run_cli(
            [
                "validate-evaluation-spec",
                "--evaluation-spec",
                str(EXAMPLE_EVALUATION_SPEC),
                "--experiment-manifest",
                str(EXAMPLE_MANIFEST),
            ]
        )
        self.assertEqual(bound_status, 0, bound_stderr)
        bound = json.loads(bound_stdout)
        self.assertEqual(
            bound["artifact_binding_status"],
            "bound_to_completed_experiment_record",
        )
        self.assertRegex(
            bound["completed_experiment_record_sha256"],
            r"^[0-9a-f]{64}$",
        )

        missing_manifest_status, _, missing_manifest_error = run_cli(
            [
                "validate-evaluation-spec",
                "--evaluation-spec",
                str(EXAMPLE_EVALUATION_SPEC),
                "--experiment-schema",
                str(ROOT / "experiment-manifest.schema.json"),
            ]
        )
        self.assertEqual(missing_manifest_status, 2)
        self.assertIn(
            "requires --experiment-manifest",
            json.loads(missing_manifest_error)["message"],
        )

        original = EXAMPLE_EVALUATION_SPEC.read_bytes()
        rejected, _, error = run_cli(
            [
                "validate-evaluation-spec",
                "--evaluation-spec",
                str(EXAMPLE_EVALUATION_SPEC),
                "--output",
                str(EXAMPLE_EVALUATION_SPEC),
            ]
        )
        self.assertEqual(rejected, 2)
        self.assertIn("--evaluation-spec", json.loads(error)["message"])
        self.assertEqual(EXAMPLE_EVALUATION_SPEC.read_bytes(), original)

    def test_evaluate_refuses_to_overwrite_response(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            response = Path(directory) / "response.txt"
            response.write_text("echo ok\n", encoding="utf-8")
            original = response.read_bytes()
            status, _, error = run_cli(
                [
                    "evaluate",
                    "--response",
                    str(response),
                    "--evaluation-spec",
                    str(EXAMPLE_EVALUATION_SPEC),
                    "--output",
                    str(response),
                ]
            )
            self.assertEqual(status, 2)
            self.assertIn("--response", json.loads(error)["message"])
            self.assertEqual(response.read_bytes(), original)

    def test_model_inspection_output_cannot_change_the_inspected_bundle(self) -> None:
        from tests.test_model_artifacts import make_dense_artifact

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact"
            artifact.mkdir()
            make_dense_artifact(artifact)
            outside = root / "inspection.json"
            status, stdout, stderr = run_cli(
                [
                    "inspect-model",
                    "--artifact-dir",
                    str(artifact),
                    "--output",
                    str(outside),
                ]
            )
            self.assertEqual(status, 0, stderr)
            self.assertEqual(stdout, "")
            report = json.loads(outside.read_text(encoding="utf-8"))
            self.assertRegex(report["report_sha256"], r"^[0-9a-f]{64}$")

            inside = artifact / "inspection.json"
            rejected, _, error = run_cli(
                [
                    "inspect-model",
                    "--artifact-dir",
                    str(artifact),
                    "--output",
                    str(inside),
                ]
            )
            self.assertEqual(rejected, 2)
            self.assertIn("outside --artifact-dir", json.loads(error)["message"])
            self.assertFalse(inside.exists())

    def test_runtime_probe_cli_uses_stable_prompt_file_and_local_probe(self) -> None:
        report = {
            "schema_version": "1.0.0",
            "runtime_probe_version": "1.1.0",
        }
        report["report_sha256"] = compute_runtime_report_sha256(report)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact"
            artifact.mkdir()
            prompt = root / "prompt.txt"
            prompt.write_text("echo hello\n", encoding="utf-8")
            output = root / "runtime.json"
            with patch(
                "cbds.model_runtime.probe_local_causal_lm", return_value=report
            ) as probe:
                status, stdout, stderr = run_cli(
                    [
                        "probe-model-runtime",
                        "--artifact-dir",
                        str(artifact),
                        "--prompt-file",
                        str(prompt),
                        "--token-cap",
                        "32",
                        "--device",
                        "cuda:0",
                        "--output",
                        str(output),
                    ]
                )
            self.assertEqual(status, 0, stderr)
            self.assertEqual(stdout, "")
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), report)
            probe.assert_called_once_with(
                artifact, "echo hello\n", token_cap=32, device="cuda:0"
            )

    def test_runtime_probe_cli_rejects_invalid_returned_report_hash(self) -> None:
        report = {
            "schema_version": "1.0.0",
            "runtime_probe_version": "1.1.0",
            "report_sha256": "a" * 64,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact"
            artifact.mkdir()
            prompt = root / "prompt.txt"
            prompt.write_text("echo hello\n", encoding="utf-8")
            output = root / "runtime.json"
            with patch(
                "cbds.model_runtime.probe_local_causal_lm", return_value=report
            ):
                status, stdout, stderr = run_cli(
                    [
                        "probe-model-runtime",
                        "--artifact-dir",
                        str(artifact),
                        "--prompt-file",
                        str(prompt),
                        "--token-cap",
                        "32",
                        "--output",
                        str(output),
                    ]
                )
        self.assertEqual(status, 2)
        self.assertEqual(stdout, "")
        self.assertIn("invalid report hash", json.loads(stderr)["message"])
        self.assertFalse(output.exists())

    def test_runtime_probe_cli_keeps_prompt_and_output_outside_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact"
            artifact.mkdir()
            prompt = root / "prompt.txt"
            prompt.write_text("x", encoding="utf-8")
            original = prompt.read_bytes()
            with patch("cbds.model_runtime.probe_local_causal_lm") as probe:
                alias_status, _, alias_error = run_cli(
                    [
                        "probe-model-runtime",
                        "--artifact-dir",
                        str(artifact),
                        "--prompt-file",
                        str(prompt),
                        "--token-cap",
                        "4",
                        "--output",
                        str(prompt),
                    ]
                )
                inside_prompt = artifact / "prompt.txt"
                inside_prompt.write_text("x", encoding="utf-8")
                inside_status, _, inside_error = run_cli(
                    [
                        "probe-model-runtime",
                        "--artifact-dir",
                        str(artifact),
                        "--prompt-file",
                        str(inside_prompt),
                        "--token-cap",
                        "4",
                    ]
                )
            self.assertEqual(alias_status, 2)
            self.assertIn("--prompt-file", json.loads(alias_error)["message"])
            self.assertEqual(inside_status, 2)
            self.assertIn("outside --artifact-dir", json.loads(inside_error)["message"])
            self.assertEqual(prompt.read_bytes(), original)
            probe.assert_not_called()

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
        self.assertIn("--pull=never", argv)
        self.assertFalse(any(item in {"-v", "--volume", "--mount"} for item in argv))

    def test_sandbox_preflight_cli_never_authorizes_execution(self) -> None:
        report = {
            "schema_version": "1.0.0",
            "decision": {
                "status": "blocked_runtime_missing",
                "blockers": ["blocked_runtime_missing"],
            },
            "untrusted_execution_authorized": False,
            "report_sha256": "a" * 64,
        }
        with patch(
            "cbds.runtime_preflight.inspect_container_runtime",
            return_value=report,
        ) as inspect:
            status, stdout, stderr = run_cli(
                [
                    "sandbox-preflight",
                    "--engine",
                    "podman",
                    "--image",
                    PINNED_IMAGE,
                ]
            )
        self.assertEqual(status, 0, stderr)
        self.assertEqual(json.loads(stdout), report)
        inspect.assert_called_once_with("podman", PINNED_IMAGE)
        self.assertFalse(json.loads(stdout)["untrusted_execution_authorized"])

    def test_stage_dry_run_is_validated_and_content_addressed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            first_status, _, first_error = run_cli(
                [
                    "train",
                    "--run-spec",
                    str(EXAMPLE_RUN_SPEC),
                    "--campaign-policy",
                    str(CAMPAIGN_POLICY),
                    "--output",
                    str(first),
                    "--dry-run",
                ]
            )
            second_status, _, second_error = run_cli(
                [
                    "train",
                    "--run-spec",
                    str(EXAMPLE_RUN_SPEC),
                    "--campaign-policy",
                    str(CAMPAIGN_POLICY),
                    "--output",
                    str(second),
                    "--dry-run",
                ]
            )
            self.assertEqual(first_status, 0, first_error)
            self.assertEqual(second_status, 0, second_error)
            first_document = json.loads(first.read_text(encoding="utf-8"))
            second_document = json.loads(second.read_text(encoding="utf-8"))
            self.assertEqual(first_document["plan_id"], second_document["plan_id"])
            self.assertEqual(
                first_document["planned_run_id"], "example-train-run-0001"
            )
            self.assertEqual(first_document["validation_status"], "valid")
            self.assertEqual(first_document["execution_status"], "validated_plan")
            self.assertEqual(
                first_document["manifest_kind"], "prospective_run_spec"
            )
            self.assertEqual(len(first_document["run_spec_sha256"]), 64)
            self.assertEqual(first_document["campaign_profile"], "screening")
            self.assertEqual(first_document["campaign_declared_seed_count"], 2)
            self.assertEqual(first_document["campaign_replicate_index"], 0)
            self.assertEqual(
                first_document["campaign_policy_sha256"],
                "7f6212d95cdbd45d7db0efbe90af43a03fb6221495d55237b91fdf6c6fc1c7fa",
            )

            mismatch_status, _, mismatch_error = run_cli(
                [
                    "compress",
                    "--run-spec",
                    str(EXAMPLE_RUN_SPEC),
                    "--campaign-policy",
                    str(CAMPAIGN_POLICY),
                    "--output",
                    str(Path(directory) / "mismatch.json"),
                    "--dry-run",
                ]
            )
            self.assertEqual(mismatch_status, 2)
            self.assertIn("does not match", json.loads(mismatch_error)["message"])

    def test_stage_plan_refuses_to_overwrite_run_spec_path_or_inode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run-spec.json"
            source.write_bytes(EXAMPLE_RUN_SPEC.read_bytes())
            policy = root / "campaign-policy.json"
            policy.write_bytes(CAMPAIGN_POLICY.read_bytes())
            original = source.read_bytes()

            same_status, _, same_error = run_cli(
                [
                    "train",
                    "--run-spec",
                    str(source),
                    "--campaign-policy",
                    str(policy),
                    "--output",
                    str(source),
                    "--dry-run",
                ]
            )
            self.assertEqual(same_status, 2)
            self.assertIn("run-spec file or inode", json.loads(same_error)["message"])
            self.assertEqual(source.read_bytes(), original)

            hardlink = root / "run-spec-hardlink.json"
            os.link(source, hardlink)
            inode_status, _, inode_error = run_cli(
                [
                    "train",
                    "--run-spec",
                    str(source),
                    "--campaign-policy",
                    str(policy),
                    "--output",
                    str(hardlink),
                    "--dry-run",
                ]
            )
            self.assertEqual(inode_status, 2)
            self.assertIn("run-spec file or inode", json.loads(inode_error)["message"])
            self.assertEqual(source.read_bytes(), original)

            policy_original = policy.read_bytes()
            policy_status, _, policy_error = run_cli(
                [
                    "train",
                    "--run-spec",
                    str(source),
                    "--campaign-policy",
                    str(policy),
                    "--output",
                    str(policy),
                    "--dry-run",
                ]
            )
            self.assertEqual(policy_status, 2)
            self.assertIn(
                "campaign-policy file or inode",
                json.loads(policy_error)["message"],
            )
            self.assertEqual(policy.read_bytes(), policy_original)

    def test_stage_plan_rejects_a_different_external_campaign_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = json.loads(CAMPAIGN_POLICY.read_text(encoding="utf-8"))
            policy["created_at"] = "2026-07-14T00:00:01+09:00"
            policy_path = root / "campaign-policy.json"
            atomic_write_json(policy_path, policy)
            output = root / "plan.json"
            status, _, error = run_cli(
                [
                    "train",
                    "--run-spec",
                    str(EXAMPLE_RUN_SPEC),
                    "--campaign-policy",
                    str(policy_path),
                    "--output",
                    str(output),
                    "--dry-run",
                ]
            )
            self.assertEqual(status, 2)
            self.assertFalse(output.exists())
            self.assertIn("campaign-policy validation failed", json.loads(error)["message"])

    def test_completed_experiment_record_is_bound_to_run_spec(self) -> None:
        status, stdout, stderr = run_cli(
            [
                "validate-experiment-record",
                "--manifest",
                str(EXAMPLE_MANIFEST),
                "--run-spec",
                str(EXAMPLE_RUN_SPEC),
                "--campaign-policy",
                str(CAMPAIGN_POLICY),
            ]
        )
        self.assertEqual(status, 0, stderr)
        document = json.loads(stdout)
        self.assertTrue(document["valid"])
        self.assertEqual(
            document["manifest_kind"], "completed_experiment_record"
        )
        self.assertEqual(document["experiment_id"], "example-dense-sft-0001")
        self.assertEqual(document["run_id"], "example-train-run-0001")
        self.assertEqual(
            document["binding_status"], "bound_to_prospective_run_spec"
        )
        self.assertEqual(len(document["run_spec_sha256"]), 64)
        self.assertEqual(document["campaign_profile"], "screening")
        self.assertEqual(
            document["campaign_policy_sha256"],
            "7f6212d95cdbd45d7db0efbe90af43a03fb6221495d55237b91fdf6c6fc1c7fa",
        )

        with tempfile.TemporaryDirectory() as directory:
            drifted = json.loads(EXAMPLE_MANIFEST.read_text(encoding="utf-8"))
            drifted["run_spec_sha256"] = "f" * 64
            drifted_path = Path(directory) / "drifted.json"
            atomic_write_json(drifted_path, drifted)
            rejected, _, rejection = run_cli(
                [
                    "validate-experiment-record",
                    "--manifest",
                    str(drifted_path),
                    "--run-spec",
                    str(EXAMPLE_RUN_SPEC),
                    "--campaign-policy",
                    str(CAMPAIGN_POLICY),
                ]
            )
            self.assertEqual(rejected, 2)
            self.assertIn("run_spec_sha256", json.loads(rejection)["message"])

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

    def test_artifact_and_manifest_outputs_cannot_overwrite_their_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dataset = root / "dataset"
            prepared, _, prepare_error = run_cli(
                [
                    "prepare",
                    "--config",
                    str(ROOT / "configs" / "benchmark-smoke.json"),
                    "--output-dir",
                    str(dataset),
                ]
            )
            self.assertEqual(prepared, 0, prepare_error)
            manifest = dataset / "manifest.json"
            original_manifest = manifest.read_bytes()
            rejected, _, error = run_cli(
                [
                    "verify-benchmark",
                    "--dataset-dir",
                    str(dataset),
                    "--output",
                    str(dataset / "verification.json"),
                ]
            )
            self.assertEqual(rejected, 2)
            self.assertIn("outside --dataset-dir", json.loads(error)["message"])
            self.assertEqual(manifest.read_bytes(), original_manifest)
            self.assertFalse((dataset / "verification.json").exists())

            completed = root / "completed.json"
            completed.write_bytes(EXAMPLE_MANIFEST.read_bytes())
            original_completed = completed.read_bytes()
            rejected, _, error = run_cli(
                [
                    "validate-experiment-record",
                    "--manifest",
                    str(completed),
                    "--run-spec",
                    str(EXAMPLE_RUN_SPEC),
                    "--campaign-policy",
                    str(CAMPAIGN_POLICY),
                    "--output",
                    str(completed),
                ]
            )
            self.assertEqual(rejected, 2)
            self.assertIn("--manifest", json.loads(error)["message"])
            self.assertEqual(completed.read_bytes(), original_completed)

            hardware = root / "hardware.json"
            atomic_write_json(hardware, valid_hardware_result())
            original_hardware = hardware.read_bytes()
            rejected, _, error = run_cli(
                ["merge-results", str(hardware), "--output", str(hardware)]
            )
            self.assertEqual(rejected, 2)
            self.assertIn("hardware result input", json.loads(error)["message"])
            self.assertEqual(hardware.read_bytes(), original_hardware)

    def test_prepare_summary_must_not_mutate_the_generated_dataset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dataset = root / "dataset"
            summary = dataset / "summary.json"
            status, _, error = run_cli(
                [
                    "prepare",
                    "--config",
                    str(ROOT / "configs" / "benchmark-smoke.json"),
                    "--output-dir",
                    str(dataset),
                    "--summary",
                    str(summary),
                ]
            )
            self.assertEqual(status, 2)
            self.assertIn("outside --output-dir", json.loads(error)["message"])
            self.assertFalse(dataset.exists())

    def test_unimplemented_training_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "plan.json"
            status, stdout, stderr = run_cli(
                [
                    "train",
                    "--run-spec",
                    str(EXAMPLE_RUN_SPEC),
                    "--campaign-policy",
                    str(CAMPAIGN_POLICY),
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
            validation = json.loads(validate_stdout)["results"][0]
            self.assertTrue(validation["valid"])
            self.assertEqual(
                validation["binding_status"],
                "unbound_standalone_validation",
            )
            self.assertIsNone(validation["completed_experiment_manifest_sha256"])
            self.assertEqual(merge_status, 0, merge_stderr)
            self.assertEqual(merge_stdout, "")
            self.assertEqual(json.loads(merged.read_text())["result_count"], 1)

    def test_hardware_validation_can_bind_a_completed_experiment(self) -> None:
        completed = json.loads(EXAMPLE_MANIFEST.read_text(encoding="utf-8"))
        result = hardware_result_for_completed_record(completed)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result_path = root / "hardware.json"
            completed_path = root / "completed.json"
            atomic_write_json(result_path, result)
            atomic_write_json(completed_path, completed)

            status, stdout, stderr = run_cli(
                [
                    "bench-hardware",
                    "validate",
                    str(result_path),
                    "--experiment-manifest",
                    str(completed_path),
                ]
            )
            self.assertEqual(status, 0, stderr)
            validation = json.loads(stdout)["results"][0]
            self.assertEqual(
                validation["binding_status"],
                "bound_to_completed_experiment_manifest",
            )
            self.assertEqual(
                validation["completed_experiment_manifest_sha256"],
                value_sha256(completed),
            )

            drifted = copy.deepcopy(result)
            drifted["artifact"]["source_manifest_sha256"] = "f" * 64
            atomic_write_json(result_path, drifted)
            rejected, _, error = run_cli(
                [
                    "bench-hardware",
                    "validate",
                    str(result_path),
                    "--experiment-manifest",
                    str(completed_path),
                ]
            )
            self.assertEqual(rejected, 2)
            self.assertIn("source_manifest_sha256", json.loads(error)["message"])

            original_completed = completed_path.read_bytes()
            alias_rejected, _, alias_error = run_cli(
                [
                    "bench-hardware",
                    "validate",
                    str(result_path),
                    "--experiment-manifest",
                    str(completed_path),
                    "--output",
                    str(completed_path),
                ]
            )
            self.assertEqual(alias_rejected, 2)
            self.assertIn("--experiment-manifest", json.loads(alias_error)["message"])
            self.assertEqual(completed_path.read_bytes(), original_completed)


if __name__ == "__main__":
    unittest.main()
