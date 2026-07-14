from __future__ import annotations

import csv
from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.manifests import canonical_json_bytes, value_sha256  # noqa: E402
from cbds.token_schedule import (  # noqa: E402
    TokenScheduleError,
    load_local_tokenizer,
    prepare_token_schedule,
    token_schedule_config_sha256,
    validate_token_schedule_artifacts,
    validate_token_schedule_config,
)
from cbds.training_corpus import prepare_training_corpus  # noqa: E402
import cbds.token_schedule as token_schedule  # noqa: E402


class TinyTokenizer:
    """One prefix/response token each, plus the scheduler's explicit EOS."""

    eos_token_id = 31
    pad_token_id = None
    bos_token_id = 30
    unk_token_id = 29
    vocab_size = 32
    cbds_library_name = "cbds-test-tokenizer"
    cbds_library_version = "1.0-test"
    is_fast = True

    def __len__(self) -> int:
        return 32

    def get_vocab(self) -> dict[str, int]:
        return {f"t{index}": index for index in range(32)}

    def encode(self, text: str, *, add_special_tokens: bool = False) -> list[int]:
        if add_special_tokens:
            raise AssertionError("the schedule must disable tokenizer-added special tokens")
        if not text:
            return []
        # The prefix ends immediately after the Response header.  A complete
        # render receives one additional response token, preserving an exact
        # token-prefix boundary while keeping fixture accounting simple.
        if text.endswith("### Response\n"):
            return [7]
        if text.startswith("### Instruction\n"):
            return [7, sum(text.encode("utf-8")) % 29]
        return [sum(text.encode("utf-8")) % 29]

    def __call__(
        self,
        text: str,
        *,
        add_special_tokens: bool,
        return_offsets_mapping: bool,
        return_attention_mask: bool,
    ) -> dict[str, object]:
        ids = self.encode(text, add_special_tokens=add_special_tokens)
        marker = "### Response\n"
        response_start = text.find(marker) + len(marker)
        if response_start == len(marker) - 1 or text.endswith(marker):
            offsets = [(0, len(text))]
        else:
            offsets = [(0, response_start), (response_start, len(text))]
        return {"input_ids": ids, "offset_mapping": offsets}


class LongTokenizer(TinyTokenizer):
    def encode(self, text: str, *, add_special_tokens: bool = False) -> list[int]:
        return [index % 29 for index, _ in enumerate(text)]

    def __call__(
        self,
        text: str,
        *,
        add_special_tokens: bool,
        return_offsets_mapping: bool,
        return_attention_mask: bool,
    ) -> dict[str, object]:
        return {
            "input_ids": self.encode(text, add_special_tokens=add_special_tokens),
            "offset_mapping": [(index, index + 1) for index in range(len(text))],
        }


class BoundaryUnstableTokenizer(TinyTokenizer):
    __call__ = None

    def encode(self, text: str, *, add_special_tokens: bool = False) -> list[int]:
        if text.endswith("### Response\n"):
            return [7]
        if text.startswith("### Instruction\n"):
            return [8, 9]
        return [1]


class CrossingOffsetTokenizer(TinyTokenizer):
    def __call__(
        self,
        text: str,
        *,
        add_special_tokens: bool,
        return_offsets_mapping: bool,
        return_attention_mask: bool,
    ) -> dict[str, object]:
        marker = "### Response\n"
        response_start = text.find(marker) + len(marker)
        if text.endswith(marker):
            return {"input_ids": [7], "offset_mapping": [(0, len(text))]}
        return {
            "input_ids": [7, 8],
            "offset_mapping": [(0, response_start + 1), (response_start + 1, len(text))],
        }


def corpus_config(source: Path) -> dict[str, object]:
    train = (source / "train.csv").read_bytes()
    card = (source / "README.md").read_bytes()
    return {
        "schema_version": "1.0.0",
        "corpus_id": "tiny-token-schedule-corpus",
        "seed": 17,
        "target_source": {
            "repository": "local/tiny",
            "revision": "a" * 40,
            "relative_path": "train.csv",
            "file_sha256": sha256(train).hexdigest(),
            "dataset_card_relative_path": "README.md",
            "dataset_card_sha256": sha256(card).hexdigest(),
            "license_provenance": {
                "upstream_declared_license": "MIT",
                "declaration_scope": "dataset_repository_level",
                "row_level_lineage": "unavailable",
                "component_license_map": "not_verified",
                "redistribution_clearance": "unresolved",
                "upstream_components": [
                    "NL2Bash",
                    "LinuxCommands",
                    "NL2CMD",
                    "InterCode-Bash",
                    "tldr-pages",
                ],
            },
            "split": "train",
            "prompt_column": "instruction",
            "completion_column": "bash",
            "expected_rows": 3,
            "expected_unique_pairs": 3,
            "duplicate_policy": "keep_first_exact_pair",
            "verification_status": "unverified_upstream_pairs",
            "excluded_relative_paths": ["test.csv"],
        },
        "support_source": {
            "generator": "cbds_prerequisite_replay",
            "version": "1.0.0",
            "license_provenance": {
                "authorship": "generated_by_this_repository",
                "project_license": "none_declared",
                "redistribution_clearance": "unresolved",
            },
            "seed": 17,
            "records_per_family": 1,
            "families": [
                "instruction_following",
                "basic_numeracy",
                "structured_json",
                "structured_yaml",
                "python_stdlib",
                "unix_regex_concepts",
            ],
            "verification_status": "deterministic_reference_generator",
        },
        "formatting": {
            "template": "### Instruction\n{prompt}\n\n### Response\n{completion}",
            "separator": "tokenizer_eos_token",
            "add_eos": True,
            "text_normalization": "crlf_and_cr_to_lf_no_unicode_normalization",
            "loss_scope": "assistant_response_tokens",
        },
    }


def schedule_config(corpus_summary: dict[str, object], **budgets: int) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "schedule_id": "tiny-offline-token-schedule",
        "seed": 101,
        "source_corpus": {
            "corpus_sha256": corpus_summary["corpus_sha256"],
            "manifest_sha256": corpus_summary["manifest_sha256"],
        },
        "corpus_eligibility": "engineering_only_unverified_not_target_policy_accepted",
        "visible_token_budgets": {
            "target": budgets.get("target", 12),
            "support": budgets.get("support", 9),
        },
        "sequence_length": 8,
        "tail_selection": {
            "reserve_visible_tokens": 8,
            "candidate_occurrences": 24,
        },
        "policies": {
            "ordering": "sha256(seed,partition,cycle,record_id)_ascending",
            "partition_interleave": "lowest_consumed_visible_fraction_target_tie",
            "oversize_record": "fail_closed_no_truncation",
            "tail_exactness": "deterministic_01_subset_sum_or_fail_closed",
            "packing": "global_order_greedy_whole_record_no_cross_sequence_split",
            "padding": "right_to_fixed_sequence_length_effective_pad_token",
            "attention": "causal_cross_example_attention_binary_nonpadding_mask_eos_delimited",
            "position_ids": "global_zero_based_monotonic_per_packed_sequence_not_reset_at_example_boundaries_including_padding",
            "labels": "response_tokens_and_explicit_eos_only_prefix_and_padding_ignore_-100",
        },
    }


class TokenScheduleTests(unittest.TestCase):
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
        self.corpus_dir = self.root / "corpus"
        self.corpus_summary = prepare_training_corpus(
            corpus_config(self.source), source_root=self.source, output_dir=self.corpus_dir
        )
        self.tokenizer_root = self.root / "tokenizer"
        self.tokenizer_root.mkdir()
        (self.tokenizer_root / "config.json").write_text(
            json.dumps(
                {
                    "model_type": "tiny",
                    "vocab_size": 32,
                    "tie_word_embeddings": True,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        (self.tokenizer_root / "tokenizer_config.json").write_text(
            json.dumps({"tokenizer_class": "TinyTokenizer"}, sort_keys=True),
            encoding="utf-8",
        )
        (self.tokenizer_root / "tokenizer.json").write_text(
            json.dumps({"version": "test"}, sort_keys=True), encoding="utf-8"
        )
        self.config = schedule_config(self.corpus_summary)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def prepare(self, name: str = "schedule") -> tuple[Path, dict[str, object]]:
        destination = self.root / name
        summary = prepare_token_schedule(
            self.config,
            corpus_dir=self.corpus_dir,
            corpus_source_root=self.source,
            tokenizer_root=self.tokenizer_root,
            output_dir=destination,
            tokenizer=TinyTokenizer(),
            model_embedding_rows=32,
        )
        return destination, summary

    def test_config_is_exact_and_preserves_engineering_only_eligibility(self) -> None:
        validated = validate_token_schedule_config(self.config)
        self.assertEqual(
            validated["corpus_eligibility"],
            "engineering_only_unverified_not_target_policy_accepted",
        )
        self.assertEqual(token_schedule_config_sha256(validated), value_sha256(validated))
        bad = json.loads(json.dumps(self.config))
        bad["corpus_eligibility"] = "claim_ready"
        with self.assertRaisesRegex(TokenScheduleError, "engineering-only"):
            validate_token_schedule_config(bad)
        bad = json.loads(json.dumps(self.config))
        bad["claim_authorized"] = True
        with self.assertRaisesRegex(TokenScheduleError, "keys differ"):
            validate_token_schedule_config(bad)

    def test_production_loader_forces_local_files_and_disables_remote_code(self) -> None:
        captured: dict[str, object] = {}

        class FakeAutoTokenizer:
            @classmethod
            def from_pretrained(cls, path: str, **kwargs: object) -> TinyTokenizer:
                captured["path"] = path
                captured.update(kwargs)
                return TinyTokenizer()

        fake_transformers = types.ModuleType("transformers")
        fake_transformers.AutoTokenizer = FakeAutoTokenizer  # type: ignore[attr-defined]
        with mock.patch.dict(sys.modules, {"transformers": fake_transformers}):
            loaded = load_local_tokenizer(self.tokenizer_root)
        self.assertIsInstance(loaded, TinyTokenizer)
        self.assertEqual(captured["path"], str(self.tokenizer_root.resolve()))
        self.assertIs(captured["local_files_only"], True)
        self.assertIs(captured["trust_remote_code"], False)
        self.assertIs(captured["use_fast"], True)

    def test_prepare_and_full_reconstruction_verify_exact_budgets(self) -> None:
        destination, prepared = self.prepare()
        verified = validate_token_schedule_artifacts(
            destination,
            corpus_dir=self.corpus_dir,
            corpus_source_root=self.source,
            tokenizer_root=self.tokenizer_root,
            tokenizer=TinyTokenizer(),
            model_embedding_rows=32,
            expected_schedule_sha256=prepared["schedule_sha256"],
            expected_manifest_sha256=prepared["manifest_sha256"],
        )
        self.assertEqual(verified["target_visible_tokens"], 12)
        self.assertEqual(verified["support_visible_tokens"], 9)
        self.assertEqual(verified["total_supervised_tokens"], 14)
        self.assertFalse(verified["training_executed"])
        self.assertFalse(verified["claim_authorized"])

        manifest = json.loads((destination / "manifest.json").read_text())
        self.assertFalse(manifest["quality_scope"]["target_policy_accepted"])
        self.assertEqual(manifest["accounting"]["target"]["occurrences"], 4)
        self.assertEqual(manifest["accounting"]["support"]["occurrences"], 3)
        self.assertEqual(manifest["accounting"]["total"]["visible_tokens"], 21)
        self.assertEqual(manifest["tokenizer"]["effective_pad_token_id"], 31)
        self.assertEqual(
            manifest["tokenizer"]["effective_pad_source"],
            "eos_fallback_attention_zero_labels_ignored",
        )

    def test_ledgers_have_response_only_counts_eos_and_pack_boundaries(self) -> None:
        destination, _ = self.prepare()
        occurrences = [
            json.loads(line)
            for line in (destination / "occurrences.jsonl").read_text().splitlines()
        ]
        self.assertEqual(len(occurrences), 7)
        for ordinal, record in enumerate(occurrences):
            self.assertEqual(record["global_ordinal"], ordinal)
            self.assertEqual(record["prefix_tokens"], 1)
            self.assertEqual(record["response_tokens"], 1)
            self.assertEqual(record["visible_tokens"], 3)
            self.assertEqual(record["supervised_tokens"], 2)
            self.assertEqual(record["eos_offset"], 2)
            self.assertNotIn("prompt", record)
            self.assertNotIn("completion", record)
        packs = [
            json.loads(line)
            for line in (destination / "packing.jsonl").read_text().splitlines()
        ]
        flattened = [
            boundary["occurrence_global_ordinal"]
            for pack in packs
            for boundary in pack["occurrences"]
        ]
        self.assertEqual(flattened, list(range(7)))
        for pack in packs:
            self.assertEqual(pack["visible_tokens"] + pack["padding_tokens"], 8)
            for boundary in pack["occurrences"]:
                self.assertEqual(boundary["eos_position"], boundary["end_exclusive"] - 1)

    def test_artifact_contains_no_corpus_plaintext(self) -> None:
        destination, _ = self.prepare()
        combined = b"".join(path.read_bytes() for path in sorted(destination.iterdir()))
        for forbidden in (b"List files", b"find . -type f", b"Print directory"):
            self.assertNotIn(forbidden, combined)

    def test_repeated_preparation_is_byte_deterministic(self) -> None:
        first, first_summary = self.prepare("first")
        second, second_summary = self.prepare("second")
        self.assertEqual(first_summary, second_summary)
        self.assertEqual(
            {item.name: item.read_bytes() for item in first.iterdir()},
            {item.name: item.read_bytes() for item in second.iterdir()},
        )

    def test_existing_or_concurrently_created_output_is_never_replaced(self) -> None:
        destination, _ = self.prepare("already-there")
        before = {item.name: item.read_bytes() for item in destination.iterdir()}
        with self.assertRaisesRegex(TokenScheduleError, "already exists"):
            prepare_token_schedule(
                self.config,
                corpus_dir=self.corpus_dir,
                corpus_source_root=self.source,
                tokenizer_root=self.tokenizer_root,
                output_dir=destination,
                tokenizer=TinyTokenizer(),
                model_embedding_rows=32,
            )
        self.assertEqual(before, {item.name: item.read_bytes() for item in destination.iterdir()})

        raced = self.root / "concurrent-output"
        original_publish = token_schedule._atomic_publish_noreplace

        def create_racer(staging: Path, requested: Path) -> None:
            requested.mkdir()
            original_publish(staging, requested)

        with mock.patch.object(
            token_schedule, "_atomic_publish_noreplace", side_effect=create_racer
        ):
            with self.assertRaisesRegex(TokenScheduleError, "already exists"):
                prepare_token_schedule(
                    self.config,
                    corpus_dir=self.corpus_dir,
                    corpus_source_root=self.source,
                    tokenizer_root=self.tokenizer_root,
                    output_dir=raced,
                    tokenizer=TinyTokenizer(),
                    model_embedding_rows=32,
                )
        self.assertTrue(raced.is_dir())
        self.assertEqual(list(raced.iterdir()), [])

    def test_unreachable_exact_budget_fails_without_partial_record(self) -> None:
        self.config = schedule_config(self.corpus_summary, target=10, support=9)
        destination = self.root / "unreachable"
        with self.assertRaisesRegex(TokenScheduleError, "unreachable.*no record was truncated"):
            prepare_token_schedule(
                self.config,
                corpus_dir=self.corpus_dir,
                corpus_source_root=self.source,
                tokenizer_root=self.tokenizer_root,
                output_dir=destination,
                tokenizer=TinyTokenizer(),
                model_embedding_rows=32,
            )
        self.assertFalse(destination.exists())

    def test_oversize_record_fails_instead_of_truncating(self) -> None:
        destination = self.root / "oversize"
        with self.assertRaisesRegex(TokenScheduleError, "no truncation is allowed"):
            prepare_token_schedule(
                self.config,
                corpus_dir=self.corpus_dir,
                corpus_source_root=self.source,
                tokenizer_root=self.tokenizer_root,
                output_dir=destination,
                tokenizer=LongTokenizer(),
                model_embedding_rows=32,
            )
        self.assertFalse(destination.exists())

    def test_prefix_unstable_tokenizer_fails_response_only_labeling(self) -> None:
        with self.assertRaisesRegex(TokenScheduleError, "not prefix-stable"):
            prepare_token_schedule(
                self.config,
                corpus_dir=self.corpus_dir,
                corpus_source_root=self.source,
                tokenizer_root=self.tokenizer_root,
                output_dir=self.root / "unstable-boundary",
                tokenizer=BoundaryUnstableTokenizer(),
                model_embedding_rows=32,
            )

    def test_boundary_crossing_token_is_visible_but_never_supervised(self) -> None:
        destination = self.root / "crossing-offset"
        prepare_token_schedule(
            self.config,
            corpus_dir=self.corpus_dir,
            corpus_source_root=self.source,
            tokenizer_root=self.tokenizer_root,
            output_dir=destination,
            tokenizer=CrossingOffsetTokenizer(),
            model_embedding_rows=32,
        )
        occurrences = [
            json.loads(line)
            for line in (destination / "occurrences.jsonl").read_text().splitlines()
        ]
        self.assertTrue(occurrences)
        for record in occurrences:
            self.assertEqual(record["boundary_crossing_tokens"], 1)
            self.assertEqual(record["boundary_ignored_response_characters"], 1)
            self.assertEqual(record["prefix_tokens"], 1)
            self.assertEqual(record["response_tokens"], 1)
            self.assertEqual(record["supervised_tokens"], 2)  # response + explicit EOS

    def test_corpus_external_pin_is_mandatory(self) -> None:
        bad = json.loads(json.dumps(self.config))
        bad["source_corpus"]["corpus_sha256"] = "0" * 64
        with self.assertRaisesRegex(Exception, "external pin"):
            prepare_token_schedule(
                bad,
                corpus_dir=self.corpus_dir,
                corpus_source_root=self.source,
                tokenizer_root=self.tokenizer_root,
                output_dir=self.root / "bad-pin",
                tokenizer=TinyTokenizer(),
                model_embedding_rows=32,
            )

    def test_raw_source_replay_is_required_not_just_structural_validity(self) -> None:
        # The prepared corpus remains structurally valid and hash-pinned, but
        # its alleged source no longer reproduces.  Scheduling must stop.
        (self.source / "train.csv").write_text(
            "instruction,bash\nChanged source,pwd\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(TokenScheduleError, "authenticated corpus verification failed"):
            prepare_token_schedule(
                self.config,
                corpus_dir=self.corpus_dir,
                corpus_source_root=self.source,
                tokenizer_root=self.tokenizer_root,
                output_dir=self.root / "source-mismatch",
                tokenizer=TinyTokenizer(),
                model_embedding_rows=32,
            )

    def test_intervening_partition_read_is_checked_against_authenticated_hash(self) -> None:
        original_read = token_schedule._read_regular

        def swapped_read(path: Path, maximum: int, label: str) -> bytes:
            payload = original_read(path, maximum, label)
            if label == "corpus target partition":
                return payload[:-2] + (b" " if payload[-2:-1] != b" " else b"x") + payload[-1:]
            return payload

        with mock.patch.object(token_schedule, "_read_regular", side_effect=swapped_read):
            with self.assertRaisesRegex(TokenScheduleError, "authenticated identity during tokenization read"):
                prepare_token_schedule(
                    self.config,
                    corpus_dir=self.corpus_dir,
                    corpus_source_root=self.source,
                    tokenizer_root=self.tokenizer_root,
                    output_dir=self.root / "intervening-swap",
                    tokenizer=TinyTokenizer(),
                    model_embedding_rows=32,
                )

    def test_ledger_and_tokenizer_file_tampering_are_detected(self) -> None:
        destination, _ = self.prepare()
        occurrence_path = destination / "occurrences.jsonl"
        occurrence_path.write_bytes(occurrence_path.read_bytes().replace(b'"visible_tokens":3', b'"visible_tokens":4', 1))
        with self.assertRaisesRegex(TokenScheduleError, "occurrence ledger differs"):
            validate_token_schedule_artifacts(
                destination,
                corpus_dir=self.corpus_dir,
                corpus_source_root=self.source,
                tokenizer_root=self.tokenizer_root,
                tokenizer=TinyTokenizer(),
                model_embedding_rows=32,
            )

        clean, _ = self.prepare("clean")
        (self.tokenizer_root / "tokenizer.json").write_text('{"version":"tampered"}')
        with self.assertRaisesRegex(TokenScheduleError, "manifest differs"):
            validate_token_schedule_artifacts(
                clean,
                corpus_dir=self.corpus_dir,
                corpus_source_root=self.source,
                tokenizer_root=self.tokenizer_root,
                tokenizer=TinyTokenizer(),
                model_embedding_rows=32,
            )

    def test_manifest_tamper_cannot_be_hidden_by_rehashing_outer_fields(self) -> None:
        destination, _ = self.prepare()
        manifest_path = destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["quality_scope"]["claim_authorized"] = True
        unsigned = dict(manifest)
        unsigned.pop("schedule_sha256")
        manifest["schedule_sha256"] = value_sha256(unsigned)
        payload = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        manifest_path.write_bytes(payload)
        (destination / "manifest.sha256").write_text(
            f"{sha256(payload).hexdigest()}  manifest.json\n"
        )
        with self.assertRaisesRegex(TokenScheduleError, "cannot attest training or authorize"):
            validate_token_schedule_artifacts(
                destination,
                corpus_dir=self.corpus_dir,
                corpus_source_root=self.source,
                tokenizer_root=self.tokenizer_root,
                tokenizer=TinyTokenizer(),
                model_embedding_rows=32,
            )

    def test_embedding_and_tokenizer_sizes_are_bound(self) -> None:
        destination, _ = self.prepare()
        manifest = json.loads((destination / "manifest.json").read_text())
        identity = manifest["tokenizer"]
        self.assertEqual(identity["sizes"]["tokenizer_size"], 32)
        self.assertEqual(identity["model_config"]["configured_vocab_size"], 32)
        self.assertEqual(identity["model_config"]["input_embedding_rows"], 32)
        self.assertEqual(
            identity["model_config"]["input_embedding_rows_source"],
            "caller_supplied_from_model_artifact_inspection",
        )
        with self.assertRaisesRegex(TokenScheduleError, "exceeds model embedding rows"):
            prepare_token_schedule(
                self.config,
                corpus_dir=self.corpus_dir,
                corpus_source_root=self.source,
                tokenizer_root=self.tokenizer_root,
                output_dir=self.root / "small-embedding",
                tokenizer=TinyTokenizer(),
                model_embedding_rows=31,
            )

    def test_manifest_and_ledger_inventory_is_exact(self) -> None:
        destination, _ = self.prepare()
        (destination / "undeclared.txt").write_text("surprise")
        with self.assertRaisesRegex(TokenScheduleError, "inventory is not exact"):
            validate_token_schedule_artifacts(
                destination,
                corpus_dir=self.corpus_dir,
                corpus_source_root=self.source,
                tokenizer_root=self.tokenizer_root,
                tokenizer=TinyTokenizer(),
                model_embedding_rows=32,
            )


if __name__ == "__main__":
    unittest.main()
