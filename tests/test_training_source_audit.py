from __future__ import annotations

import copy
import csv
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.manifests import canonical_json_bytes, load_document, value_sha256  # noqa: E402
import cbds.training_source_audit as audit_module  # noqa: E402
from cbds.training_corpus import prepare_training_corpus  # noqa: E402
from cbds.training_source_audit import (  # noqa: E402
    TrainingSourceAuditError,
    classifier_policy,
    classify_target_command_lexically,
    normalize_prompt_for_collision,
    prepare_training_source_audit,
    validate_training_source_audit_artifacts,
)


PINNED_CONFIG = ROOT / "configs" / "training-corpus-pilot.json"


def csv_payload(rows: list[tuple[str, str]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(["nl", "bash"])
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def fixture_config(payload: bytes, card: bytes, rows: int) -> dict[str, object]:
    config = copy.deepcopy(load_document(PINNED_CONFIG))
    target = config["target_source"]
    target["repository"] = "local/source-audit-fixture"
    target["revision"] = "b" * 40
    target["file_sha256"] = sha256(payload).hexdigest()
    target["dataset_card_sha256"] = sha256(card).hexdigest()
    target["expected_rows"] = rows
    target["expected_unique_pairs"] = rows
    config["corpus_id"] = "source-audit-raw-fixture"
    config["seed"] = 73
    config["support_source"]["seed"] = 73
    config["support_source"]["records_per_family"] = 1
    return config


def parse_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def resign_manifest(root: Path, manifest: dict[str, object]) -> None:
    unsigned = dict(manifest)
    unsigned.pop("audit_sha256", None)
    manifest["audit_sha256"] = value_sha256(unsigned)
    payload = (
        json.dumps(manifest, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")
    (root / "manifest.json").write_bytes(payload)
    (root / "manifest.sha256").write_bytes(
        f"{sha256(payload).hexdigest()}  manifest.json\n".encode("ascii")
    )


class LexicalClassifierTests(unittest.TestCase):
    def test_quoted_separators_and_single_quoted_substitution_remain_literal(self) -> None:
        quoted = classify_target_command_lexically(
            "grep -E 'a|b;&&' input.txt | sort"
        )
        self.assertEqual(quoted["status"], "static_candidate")
        self.assertEqual(quoted["observed_utilities"], ["grep", "sort"])

        literal = classify_target_command_lexically(
            "printf '%s\\n' '$(date); | <(sort input)'"
        )
        self.assertEqual(literal["status"], "static_candidate")
        self.assertEqual(literal["observed_utilities"], ["printf"])

    def test_dynamic_substitutions_and_wrappers_fail_closed(self) -> None:
        examples = {
            'printf "%s" "$(date)"': "command_substitution",
            "cat <(sort input.txt)": "process_substitution",
            'eval "$generated"': "eval_or_source",
            "source ./setup.sh": "eval_or_source",
            "bash -c 'find . -type f'": "shell_wrapper",
            "timeout 2 sh -c 'find .'": "shell_wrapper",
            "nohup curl https://example.com/data": "dynamic_execution",
            "awk 'BEGIN { system(\"curl example.com\") }'": "dynamic_execution",
            "sed 'e curl example.com' input.txt": "dynamic_execution",
            "tar --checkpoint=1 --checkpoint-action=exec='curl example.com' -cf out.tar input": "dynamic_execution",
            "./ls": "dynamic_execution",
            "$TOOLS/ls": "dynamic_execution",
            "find . -exec rm {} \\;": "dynamic_execution",
            "python3 -c 'print(1)'": "dynamic_execution",
        }
        for command, reason in examples.items():
            with self.subTest(command=command):
                result = classify_target_command_lexically(command)
                self.assertEqual(result["status"], "rejected")
                self.assertIn(reason, result["reason_codes"])
                self.assertFalse(result["target_policy_accepted"])

    def test_placeholders_ui_paths_and_off_target_tools_are_rejected(self) -> None:
        examples = {
            "cp path/to/file output": "placeholder_or_template",
            "<Spacebar>": "non_shell_ui_label",
            "cat /etc/passwd": "absolute_system_path",
            "cat /'etc'/passwd": "absolute_system_path",
            "dd if=/dev/sda of=image.bin": "absolute_device_path",
            "curl https://example.com/data": "utility_not_allowlisted",
        }
        for command, reason in examples.items():
            with self.subTest(command=command):
                self.assertIn(
                    reason,
                    classify_target_command_lexically(command)["reason_codes"],
                )

        for malformed in ("cat |", "cat >", "cat > ; curl example.com"):
            with self.subTest(malformed=malformed):
                self.assertIn(
                    "lexical_parse_failed",
                    classify_target_command_lexically(malformed)["reason_codes"],
                )
        self.assertIn(
            "lexical_parse_failed",
            classify_target_command_lexically("printf ok\ncurl example.com")[
                "reason_codes"
            ],
        )

    def test_prompt_normalization_and_policy_are_deterministic(self) -> None:
        self.assertEqual(
            normalize_prompt_for_collision("  Show\tＦＩＬＥＳ  "),
            normalize_prompt_for_collision("show files"),
        )
        self.assertEqual(classifier_policy(), classifier_policy())
        self.assertFalse(
            classifier_policy()["classification_contract"]["training_eligible"]
        )


class TrainingSourceAuditArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.rows = [
            ("safe find", "find . -type f"),
            ("quoted separators", "grep -E 'a|b;&&' input.txt | sort"),
            ("quoted substitution literal", "printf '%s\\n' '$(date); |'"),
            ("JSON names", "jq -r '.name' input.json"),
            ("Show FILES", "ls"),
            (" show   files ", "find . -maxdepth 1"),
            ("copy template", "cp path/to/file output"),
            ("pause game", "<Spacebar>"),
            ("show date dynamically", 'printf "%s" "$(date)"'),
            ("sort through process input", "cat <(sort input.txt)"),
            ("evaluate generated input", 'eval "$generated"'),
            ("load setup", "source ./setup.sh"),
            ("wrap shell", "bash -c 'find . -type f'"),
            ("read accounts", "cat /etc/passwd"),
            ("copy device", "dd if=/dev/sda of=image.bin"),
            ("download", "curl https://example.com/data"),
            ("find and execute", "find . -exec rm {} \\;"),
            ("inline Python", "python3 -c 'print(1)'"),
        ]
        payload = csv_payload(self.rows)
        card = b"fixture card; upstream rows are unverified\n"
        (self.source / "train.csv").write_bytes(payload)
        (self.source / "README.md").write_bytes(card)
        (self.source / "test.csv").write_text("excluded\n", encoding="utf-8")
        self.raw = self.root / "raw"
        self.raw_summary = prepare_training_corpus(
            fixture_config(payload, card, len(self.rows)),
            source_root=self.source,
            output_dir=self.raw,
        )
        self.audit = self.root / "audit"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def prepare(self, output: Path | None = None) -> dict[str, object]:
        return prepare_training_source_audit(
            audit_id="fixture-source-audit",
            corpus_dir=self.raw,
            source_root=self.source,
            output_dir=self.audit if output is None else output,
            expected_corpus_sha256=self.raw_summary["corpus_sha256"],
            expected_manifest_sha256=self.raw_summary["manifest_sha256"],
        )

    def source_prompt_map(self) -> dict[str, str]:
        return {
            record["record_id"]: record["prompt"]
            for record in parse_jsonl(self.raw / "target.jsonl")
        }

    def test_emits_candidates_hash_only_rejections_and_hard_false_scope(self) -> None:
        summary = self.prepare()
        verified = validate_training_source_audit_artifacts(
            self.audit,
            expected_audit_sha256=summary["audit_sha256"],
            expected_manifest_sha256=summary["manifest_sha256"],
            raw_corpus_dir=self.raw,
            raw_source_root=self.source,
            raw_expected_corpus_sha256=self.raw_summary["corpus_sha256"],
            raw_expected_manifest_sha256=self.raw_summary["manifest_sha256"],
            require_authenticated=True,
        )
        self.assertTrue(verified["authenticated"])
        self.assertTrue(verified["artifact_pins_verified"])
        self.assertTrue(verified["raw_source_reverified"])
        self.assertFalse(verified["training_eligible"])
        self.assertFalse(verified["target_policy_accepted"])
        self.assertFalse(verified["claim_authorized"])

        candidates = parse_jsonl(self.audit / "accepted-candidates.jsonl")
        candidate_prompts = {record["prompt"] for record in candidates}
        self.assertEqual(
            candidate_prompts,
            {"safe find", "quoted separators", "quoted substitution literal", "JSON names"},
        )
        for record in candidates:
            classification = record["classification"]
            self.assertEqual(classification["status"], "static_candidate")
            self.assertFalse(classification["ast_parsed"])
            self.assertFalse(classification["execution_verified"])
            self.assertFalse(classification["training_eligible"])

        rejection_payload = (self.audit / "rejections.jsonl").read_bytes()
        rejections = parse_jsonl(self.audit / "rejections.jsonl")
        self.assertTrue(rejections)
        for record in rejections:
            self.assertNotIn("prompt", record)
            self.assertNotIn("completion", record)
        for prompt, command in self.rows:
            if prompt not in candidate_prompts:
                self.assertNotIn(prompt.encode(), rejection_payload)
                self.assertNotIn(command.encode(), rejection_payload)

        manifest = json.loads((self.audit / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["quality_scope"]["classification_scope"], "stdlib_lexical_prefilter_only")
        self.assertFalse(manifest["quality_scope"]["ast_parsed"])
        self.assertFalse(manifest["quality_scope"]["execution_verified"])
        self.assertFalse(manifest["quality_scope"]["target_policy_accepted"])
        self.assertFalse(manifest["evaluation_bindings"]["overlap_analysis_performed"])
        self.assertTrue(manifest["raw_source"]["source_replay_verified"])
        self.assertIn("record_sequence_sha256", manifest["files"][0])
        self.assertIn("record_sequence_sha256", manifest["files"][1])
        self.assertEqual(len(manifest["preparer"]["transformation_sources"]), 3)
        self.assertTrue(manifest["preparer"]["runtime"]["python_version"])
        self.assertTrue(manifest["preparer"]["runtime"]["unicode_database_version"])
        utility_labels = {
            item["utility"] for item in manifest["histograms"]["utilities"]
        }
        self.assertNotIn("curl", utility_labels)
        self.assertIn("__not_allowlisted__", utility_labels)
        self.assertNotIn(b"curl https://example.com/data", b"".join(
            path.read_bytes() for path in self.audit.iterdir()
        ))

    def test_audit_pins_without_raw_replay_are_not_consumable(self) -> None:
        summary = self.prepare()
        inspected = validate_training_source_audit_artifacts(
            self.audit,
            expected_audit_sha256=summary["audit_sha256"],
            expected_manifest_sha256=summary["manifest_sha256"],
        )
        self.assertTrue(inspected["artifact_pins_verified"])
        self.assertFalse(inspected["raw_source_reverified"])
        self.assertFalse(inspected["authenticated"])
        with self.assertRaisesRegex(TrainingSourceAuditError, "raw provenance replay"):
            validate_training_source_audit_artifacts(
                self.audit,
                expected_audit_sha256=summary["audit_sha256"],
                expected_manifest_sha256=summary["manifest_sha256"],
                require_authenticated=True,
            )

    def test_normalized_prompt_multi_completion_rejects_every_colliding_row(self) -> None:
        self.prepare()
        prompts = self.source_prompt_map()
        reasons = {
            prompts[record["source_record_id"]]: record["reason_codes"]
            for record in parse_jsonl(self.audit / "rejections.jsonl")
        }
        self.assertIn("ambiguous_normalized_prompt", reasons["Show FILES"])
        self.assertIn("ambiguous_normalized_prompt", reasons[" show   files "])
        manifest = json.loads((self.audit / "manifest.json").read_text(encoding="utf-8"))
        collisions = manifest["histograms"]["normalized_prompt_collisions"]
        self.assertEqual(collisions["ambiguous_groups"], 1)
        self.assertEqual(collisions["ambiguous_records"], 2)

    def test_source_commands_are_never_executed(self) -> None:
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("executed")), mock.patch.object(
            os, "system", side_effect=AssertionError("executed")
        ):
            summary = self.prepare()
        self.assertEqual(summary["source_records"], len(self.rows))

    def test_both_external_pins_and_source_replay_are_mandatory(self) -> None:
        with self.assertRaisesRegex(TrainingSourceAuditError, "expected_corpus_sha256"):
            prepare_training_source_audit(
                audit_id="fixture-source-audit",
                corpus_dir=self.raw,
                source_root=self.source,
                output_dir=self.audit,
                expected_corpus_sha256=None,  # type: ignore[arg-type]
                expected_manifest_sha256=self.raw_summary["manifest_sha256"],
            )
        with self.assertRaisesRegex(TrainingSourceAuditError, "external pin"):
            prepare_training_source_audit(
                audit_id="fixture-source-audit",
                corpus_dir=self.raw,
                source_root=self.source,
                output_dir=self.audit,
                expected_corpus_sha256=self.raw_summary["corpus_sha256"],
                expected_manifest_sha256="0" * 64,
            )

        wrong_source = self.root / "wrong-source"
        wrong_source.mkdir()
        with self.assertRaisesRegex(TrainingSourceAuditError, "source"):
            prepare_training_source_audit(
                audit_id="fixture-source-audit",
                corpus_dir=self.raw,
                source_root=wrong_source,
                output_dir=self.audit,
                expected_corpus_sha256=self.raw_summary["corpus_sha256"],
                expected_manifest_sha256=self.raw_summary["manifest_sha256"],
            )

    def test_artifact_is_byte_deterministic(self) -> None:
        first = self.prepare()
        second_root = self.root / "audit-again"
        second = self.prepare(second_root)
        self.assertEqual(first, second)
        for name in (
            "accepted-candidates.jsonl",
            "rejections.jsonl",
            "manifest.json",
            "manifest.sha256",
        ):
            self.assertEqual((self.audit / name).read_bytes(), (second_root / name).read_bytes())

    def test_ledger_and_resigned_claim_tampering_fail_closed(self) -> None:
        summary = self.prepare()
        candidate = self.audit / "accepted-candidates.jsonl"
        payload = candidate.read_bytes()
        candidate.write_bytes(payload.replace(b"safe find", b"safe xind", 1))
        with self.assertRaisesRegex(TrainingSourceAuditError, "file identity"):
            validate_training_source_audit_artifacts(self.audit)

        candidate.write_bytes(payload)
        manifest_path = self.audit / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["quality_scope"]["target_policy_accepted"] = True
        resign_manifest(self.audit, manifest)
        with self.assertRaisesRegex(TrainingSourceAuditError, "claim boundary"):
            validate_training_source_audit_artifacts(self.audit)
        with self.assertRaisesRegex(TrainingSourceAuditError, "external pin"):
            validate_training_source_audit_artifacts(
                self.audit,
                expected_audit_sha256=summary["audit_sha256"],
                expected_manifest_sha256=summary["manifest_sha256"],
                require_authenticated=True,
            )

    def test_resigned_candidate_forgery_requires_raw_replay(self) -> None:
        self.prepare()
        candidates = parse_jsonl(self.audit / "accepted-candidates.jsonl")
        forged = candidates[0]
        forged["prompt"] = "forged but lexically harmless prompt"
        forged["normalized_prompt_sha256"] = audit_module._prompt_digest(
            normalize_prompt_for_collision(forged["prompt"])
        )
        core = dict(forged)
        core.pop("schema_version")
        core.pop("audit_record_id")
        core.pop("audit_record_sha256")
        forged_digest = value_sha256(core)
        forged["audit_record_sha256"] = forged_digest
        forged["audit_record_id"] = f"tsa-c-{forged_digest[:24]}"
        candidate_payload = b"".join(
            canonical_json_bytes(record) + b"\n" for record in candidates
        )
        (self.audit / "accepted-candidates.jsonl").write_bytes(candidate_payload)

        rejections = parse_jsonl(self.audit / "rejections.jsonl")
        manifest_path = self.audit / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"][0] = audit_module._file_declaration(
            "accepted-candidates.jsonl", candidate_payload, candidates
        )
        all_records = sorted(
            candidates + rejections, key=lambda record: record["source_ordinal"]
        )
        decisions = [
            {
                "source_record_id": record["source_record_id"],
                "source_record_sha256": record["source_record_sha256"],
                "source_ordinal": record["source_ordinal"],
                "decision": (
                    "static_candidate"
                    if record["record_type"].endswith("static-candidate")
                    else "rejected"
                ),
                "audit_record_sha256": record["audit_record_sha256"],
            }
            for record in all_records
        ]
        manifest["decision_sequence_sha256"] = value_sha256(
            {
                "contract": "cbds.training-source-audit-decision-sequence",
                "version": audit_module.AUDIT_SCHEMA_VERSION,
                "decisions": decisions,
            }
        )
        resign_manifest(self.audit, manifest)

        structurally_valid = validate_training_source_audit_artifacts(self.audit)
        self.assertTrue(structurally_valid["valid"])
        self.assertFalse(structurally_valid["authenticated"])
        forged_manifest_payload = manifest_path.read_bytes()
        with self.assertRaisesRegex(TrainingSourceAuditError, "does not reproduce"):
            validate_training_source_audit_artifacts(
                self.audit,
                expected_audit_sha256=manifest["audit_sha256"],
                expected_manifest_sha256=sha256(forged_manifest_payload).hexdigest(),
                raw_corpus_dir=self.raw,
                raw_source_root=self.source,
                raw_expected_corpus_sha256=self.raw_summary["corpus_sha256"],
                raw_expected_manifest_sha256=self.raw_summary["manifest_sha256"],
                require_authenticated=True,
            )

    def test_failed_publication_leaves_no_partial_or_staging_directory(self) -> None:
        original = audit_module._write_new_at
        calls = 0

        def fail_second_write(
            directory_descriptor: int, name: str, payload: bytes
        ) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected publication failure")
            original(directory_descriptor, name, payload)

        with mock.patch.object(
            audit_module, "_write_new_at", side_effect=fail_second_write
        ):
            with self.assertRaisesRegex(OSError, "injected publication failure"):
                self.prepare()
        self.assertFalse(self.audit.exists())
        self.assertFalse(
            any(path.name.startswith(".audit.staging-") for path in self.root.iterdir())
        )

    def test_symlinked_or_replaced_audit_root_fails_closed(self) -> None:
        self.prepare()
        alias = self.root / "audit-alias"
        alias.symlink_to(self.audit, target_is_directory=True)
        with self.assertRaisesRegex(TrainingSourceAuditError, "directory path"):
            validate_training_source_audit_artifacts(alias)

        moved = self.root / "audit-original"
        original_validator = audit_module._validate_training_source_audit_artifacts_from_fd

        def replace_after_validation(*args: object, **kwargs: object) -> dict[str, object]:
            result = original_validator(*args, **kwargs)
            self.audit.rename(moved)
            self.audit.mkdir()
            return result

        with mock.patch.object(
            audit_module,
            "_validate_training_source_audit_artifacts_from_fd",
            side_effect=replace_after_validation,
        ):
            with self.assertRaisesRegex(TrainingSourceAuditError, "root path changed"):
                validate_training_source_audit_artifacts(self.audit)

    def test_existing_output_is_not_overwritten(self) -> None:
        self.audit.mkdir()
        sentinel = self.audit / "sentinel"
        sentinel.write_text("keep", encoding="utf-8")
        with self.assertRaisesRegex(TrainingSourceAuditError, "already exists"):
            self.prepare()
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")
        self.assertFalse(
            any(path.name.startswith(".audit.staging-") for path in self.root.iterdir())
        )


if __name__ == "__main__":
    unittest.main()
