from __future__ import annotations

import copy
import csv
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cbds.manifests import canonical_json_bytes, load_document, value_sha256
from cbds import training_corpus as training_corpus_module
from cbds.training_corpus import (
    CORPUS_SCHEMA_VERSION,
    TrainingCorpusError,
    load_training_corpus_config,
    prepare_training_corpus,
    training_corpus_config_sha256,
    validate_training_corpus_artifacts,
    validate_training_corpus_config,
)


ROOT = Path(__file__).resolve().parents[1]
PINNED_CONFIG = ROOT / "configs" / "training-corpus-pilot.json"


def csv_payload(rows: list[tuple[str, str]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(["nl", "bash"])
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def fixture_config(
    payload: bytes,
    card: bytes,
    *,
    rows: int,
    unique: int,
) -> dict[str, object]:
    config = copy.deepcopy(load_document(PINNED_CONFIG))
    target = config["target_source"]
    target["repository"] = "example/NL2SH-fixture"
    target["revision"] = "1" * 40
    target["file_sha256"] = sha256(payload).hexdigest()
    target["dataset_card_sha256"] = sha256(card).hexdigest()
    target["expected_rows"] = rows
    target["expected_unique_pairs"] = unique
    support = config["support_source"]
    support["records_per_family"] = 3
    return config


def resign_manifest(output: Path, manifest: dict[str, object]) -> None:
    unsigned = dict(manifest)
    unsigned.pop("corpus_sha256", None)
    manifest["corpus_sha256"] = value_sha256(unsigned)
    payload = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    (output / "manifest.json").write_bytes(payload)
    (output / "manifest.sha256").write_bytes(
        f"{sha256(payload).hexdigest()}  manifest.json\n".encode("ascii")
    )


class TrainingCorpusConfigTests(unittest.TestCase):
    def test_checked_in_pilot_config_is_valid_and_content_addressed(self) -> None:
        config = load_training_corpus_config(PINNED_CONFIG)
        self.assertEqual(config["schema_version"], CORPUS_SCHEMA_VERSION)
        self.assertEqual(config["target_source"]["split"], "train")
        self.assertIn("test.csv", config["target_source"]["excluded_relative_paths"])
        self.assertEqual(training_corpus_config_sha256(config), value_sha256(config))
        records = training_corpus_module._support_records(config)
        self.assertEqual(len(records), 6 * 512)
        self.assertEqual(
            len({(record["prompt"], record["completion"]) for record in records}),
            len(records),
        )

    def test_test_split_and_quality_laundering_are_rejected(self) -> None:
        config = copy.deepcopy(load_document(PINNED_CONFIG))
        config["target_source"]["split"] = "test"
        with self.assertRaisesRegex(TrainingCorpusError, "split"):
            validate_training_corpus_config(config)

        config = copy.deepcopy(load_document(PINNED_CONFIG))
        config["target_source"]["verification_status"] = "verified"
        with self.assertRaisesRegex(TrainingCorpusError, "verification_status"):
            validate_training_corpus_config(config)

    def test_formatting_and_support_family_order_are_frozen(self) -> None:
        config = copy.deepcopy(load_document(PINNED_CONFIG))
        config["formatting"]["loss_scope"] = "all_non_padding_tokens"
        with self.assertRaisesRegex(TrainingCorpusError, "formatting"):
            validate_training_corpus_config(config)

        config = copy.deepcopy(load_document(PINNED_CONFIG))
        config["support_source"]["families"].reverse()
        with self.assertRaisesRegex(TrainingCorpusError, "ordered family"):
            validate_training_corpus_config(config)

    def test_seed_and_relative_paths_have_effective_canonical_meaning(self) -> None:
        config = copy.deepcopy(load_document(PINNED_CONFIG))
        config["support_source"]["seed"] += 1
        with self.assertRaisesRegex(TrainingCorpusError, "root seed drives"):
            validate_training_corpus_config(config)

        config = copy.deepcopy(load_document(PINNED_CONFIG))
        config["target_source"]["relative_path"] = "data//train.csv"
        with self.assertRaisesRegex(TrainingCorpusError, "canonical safe relative"):
            validate_training_corpus_config(config)


class PreparedTrainingCorpusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.card = b"license: mit\nfixture dataset card\n"
        self.rows = [
            ("list files", "ls"),
            ("show disk use", "df -h"),
            ("list files", "ls"),
            ("find text, including commas", 'grep -E "a,b" input.txt'),
        ]
        self.payload = csv_payload(self.rows)
        (self.source / "train.csv").write_bytes(self.payload)
        (self.source / "README.md").write_bytes(self.card)
        (self.source / "test.csv").write_text(
            "DO-NOT-IMPORT-TEST-SENTINEL\n", encoding="utf-8"
        )
        self.config = fixture_config(
            self.payload, self.card, rows=len(self.rows), unique=3
        )
        self.output = self.root / "prepared"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def prepare(self) -> dict[str, object]:
        return prepare_training_corpus(
            self.config, source_root=self.source, output_dir=self.output
        )

    def test_prepare_and_verify_exact_two_partition_artifact(self) -> None:
        summary = self.prepare()
        self.assertEqual(summary["target_records"], 3)
        self.assertEqual(summary["support_records"], 18)
        self.assertFalse(summary["test_source_imported"])
        self.assertFalse(summary["claim_authorized"])
        self.assertEqual(
            {item.name for item in self.output.iterdir()},
            {"target.jsonl", "support.jsonl", "manifest.json", "manifest.sha256"},
        )

        verified = validate_training_corpus_artifacts(
            self.output,
            expected_corpus_sha256=summary["corpus_sha256"],
            expected_manifest_sha256=summary["manifest_sha256"],
        )
        self.assertTrue(verified["valid"])
        self.assertTrue(verified["authenticated"])
        self.assertEqual(verified["target_records"], 3)
        self.assertEqual(verified["support_records"], 18)
        combined = b"".join(path.read_bytes() for path in self.output.iterdir())
        self.assertNotIn(b"DO-NOT-IMPORT-TEST-SENTINEL", combined)

    def test_preparation_is_byte_deterministic_across_output_directories(self) -> None:
        first = self.prepare()
        second_output = self.root / "prepared-again"
        second = prepare_training_corpus(
            self.config, source_root=self.source, output_dir=second_output
        )
        self.assertEqual(first, second)
        for name in ("target.jsonl", "support.jsonl", "manifest.json", "manifest.sha256"):
            self.assertEqual(
                (self.output / name).read_bytes(), (second_output / name).read_bytes()
            )

    def test_target_records_keep_first_exact_pair_and_preserve_unverified_status(self) -> None:
        self.prepare()
        records = [
            json.loads(line)
            for line in (self.output / "target.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual([record["source"]["row_number"] for record in records], [2, 3, 5])
        self.assertTrue(
            all(
                record["source"]["verification_status"]
                == "unverified_upstream_pairs"
                for record in records
            )
        )

    def test_support_generator_covers_every_frozen_family_without_duplicates(self) -> None:
        self.prepare()
        records = [
            json.loads(line)
            for line in (self.output / "support.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        families: dict[str, int] = {}
        pairs: set[tuple[str, str]] = set()
        for record in records:
            families[record["family"]] = families.get(record["family"], 0) + 1
            pairs.add((record["prompt"], record["completion"]))
        self.assertEqual(
            families,
            {
                "instruction_following": 3,
                "basic_numeracy": 3,
                "structured_json": 3,
                "structured_yaml": 3,
                "python_stdlib": 3,
                "unix_regex_concepts": 3,
            },
        )
        self.assertEqual(len(pairs), len(records))

    def test_source_and_dataset_card_hashes_are_both_enforced(self) -> None:
        wrong = copy.deepcopy(self.config)
        wrong["target_source"]["file_sha256"] = "0" * 64
        with self.assertRaisesRegex(TrainingCorpusError, "source SHA-256"):
            prepare_training_corpus(
                wrong, source_root=self.source, output_dir=self.output
            )

        wrong = copy.deepcopy(self.config)
        wrong["target_source"]["dataset_card_sha256"] = "0" * 64
        with self.assertRaisesRegex(TrainingCorpusError, "dataset-card SHA-256"):
            prepare_training_corpus(
                wrong, source_root=self.source, output_dir=self.output
            )

    def test_huggingface_style_snapshot_symlink_is_pinned_and_supported(self) -> None:
        blob = self.root / "blob"
        blob.write_bytes(self.payload)
        (self.source / "train.csv").unlink()
        os.symlink(os.path.relpath(blob, self.source), self.source / "train.csv")
        summary = self.prepare()
        self.assertEqual(summary["target_records"], 3)

    def test_malformed_unquoted_csv_quote_is_rejected(self) -> None:
        malformed = b'nl,bash\r\ninvalid "quote,ls\r\n'
        (self.source / "train.csv").write_bytes(malformed)
        config = fixture_config(malformed, self.card, rows=1, unique=1)
        with self.assertRaisesRegex(TrainingCorpusError, "RFC 4180"):
            prepare_training_corpus(
                config, source_root=self.source, output_dir=self.output
            )

    def test_existing_output_is_never_overwritten(self) -> None:
        self.output.mkdir()
        sentinel = self.output / "sentinel"
        sentinel.write_text("keep", encoding="utf-8")
        with self.assertRaisesRegex(TrainingCorpusError, "already exists"):
            self.prepare()
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")

    def test_concurrent_empty_destination_is_not_replaced(self) -> None:
        original = training_corpus_module._rename_directory_noreplace

        def create_racing_destination(
            parent_descriptor: int, source_name: str, destination_name: str
        ) -> None:
            os.mkdir(destination_name, dir_fd=parent_descriptor)
            original(parent_descriptor, source_name, destination_name)

        with patch.object(
            training_corpus_module,
            "_rename_directory_noreplace",
            side_effect=create_racing_destination,
        ):
            with self.assertRaisesRegex(TrainingCorpusError, "already exists"):
                self.prepare()
        self.assertTrue(self.output.is_dir())
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertFalse(any(path.name.endswith(".tmp") for path in self.root.iterdir()))

    def test_partition_tamper_and_extra_members_fail_closed(self) -> None:
        self.prepare()
        target = self.output / "target.jsonl"
        payload = target.read_bytes()
        target.write_bytes(payload.replace(b"list files", b"list xiles", 1))
        with self.assertRaisesRegex(TrainingCorpusError, "file identity"):
            validate_training_corpus_artifacts(self.output)

        target.write_bytes(payload)
        (self.output / "extra.txt").write_text("extra", encoding="utf-8")
        with self.assertRaisesRegex(TrainingCorpusError, "inventory"):
            validate_training_corpus_artifacts(self.output)

    def test_root_path_swap_during_verification_fails_closed(self) -> None:
        self.prepare()
        moved = self.root / "moved-corpus"
        original = training_corpus_module._read_regular_at
        swapped = False

        def swap_root_then_read(
            directory_descriptor: int, name: str, maximum: int
        ) -> bytes:
            nonlocal swapped
            if not swapped:
                os.rename(self.output, moved)
                self.output.mkdir()
                swapped = True
            return original(directory_descriptor, name, maximum)

        with patch.object(
            training_corpus_module,
            "_read_regular_at",
            side_effect=swap_root_then_read,
        ):
            with self.assertRaisesRegex(TrainingCorpusError, "corpus root"):
                validate_training_corpus_artifacts(self.output)

    def test_manifest_config_tamper_fails_even_if_outer_hashes_are_rewritten(self) -> None:
        self.prepare()
        path = self.output / "manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["target_source"]["license_provenance"][
            "redistribution_clearance"
        ] = "invented-clearance"
        resign_manifest(self.output, manifest)
        with self.assertRaisesRegex(TrainingCorpusError, "license_provenance"):
            validate_training_corpus_artifacts(self.output)

    def test_resigned_quality_laundering_and_support_reordering_fail_closed(self) -> None:
        self.prepare()
        manifest_path = self.output / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["quality_scope"]["target"] = "verified"
        resign_manifest(self.output, manifest)
        with self.assertRaisesRegex(TrainingCorpusError, "research claim"):
            validate_training_corpus_artifacts(self.output)

        # Restore a fresh artifact, then reorder two otherwise valid support
        # records and honestly recompute every enclosing digest.  Semantic
        # generator order remains part of the contract and must still fail.
        second = self.root / "prepared-reordered"
        prepare_training_corpus(
            self.config, source_root=self.source, output_dir=second
        )
        support_path = second / "support.jsonl"
        lines = support_path.read_bytes().splitlines(keepends=True)
        lines[0], lines[1] = lines[1], lines[0]
        support_payload = b"".join(lines)
        support_path.write_bytes(support_payload)
        manifest = json.loads((second / "manifest.json").read_text(encoding="utf-8"))
        support = next(
            item for item in manifest["partitions"] if item["partition"] == "support"
        )
        support["bytes"] = len(support_payload)
        support["sha256"] = sha256(support_payload).hexdigest()
        support["record_sequence_sha256"] = value_sha256(
            {
                "contract": "cbds.training-record-sequence",
                "version": "1.0.0",
                "partition": "support",
                "record_sha256s": [
                    json.loads(line)["record_sha256"] for line in lines
                ],
            }
        )
        resign_manifest(second, manifest)
        with self.assertRaisesRegex(TrainingCorpusError, "frozen generator order"):
            validate_training_corpus_artifacts(second)

    def test_external_hash_pins_are_enforced(self) -> None:
        summary = self.prepare()
        with self.assertRaisesRegex(TrainingCorpusError, "external pin"):
            validate_training_corpus_artifacts(
                self.output, expected_corpus_sha256="0" * 64
            )
        with self.assertRaisesRegex(TrainingCorpusError, "external pin"):
            validate_training_corpus_artifacts(
                self.output, expected_manifest_sha256="0" * 64
            )

        inspected = validate_training_corpus_artifacts(self.output)
        self.assertTrue(inspected["valid"])
        self.assertFalse(inspected["authenticated"])
        with self.assertRaisesRegex(TrainingCorpusError, "authenticated corpus identity"):
            validate_training_corpus_artifacts(
                self.output, require_authenticated=True
            )
        replayed = validate_training_corpus_artifacts(
            self.output,
            source_root=self.source,
            require_authenticated=True,
        )
        self.assertTrue(replayed["authenticated"])
        self.assertTrue(replayed["authentication"]["source_replay_verified"])
        self.assertEqual(replayed["corpus_sha256"], summary["corpus_sha256"])

    def test_fully_rehashed_off_source_forgery_is_only_unauthenticated_inspection(self) -> None:
        self.prepare()
        target_path = self.output / "target.jsonl"
        records = [json.loads(line) for line in target_path.read_bytes().splitlines()]
        records[0]["prompt"] = "forged off-source prompt"
        core = {
            key: records[0][key]
            for key in (
                "schema_version",
                "partition",
                "family",
                "prompt",
                "completion",
                "source",
            )
        }
        digest = value_sha256(core)
        records[0]["record_sha256"] = digest
        records[0]["record_id"] = f"tr-{digest[:24]}"
        target_payload = b"".join(
            canonical_json_bytes(record) + b"\n" for record in records
        )
        target_path.write_bytes(target_payload)

        manifest = json.loads((self.output / "manifest.json").read_text(encoding="utf-8"))
        target = next(
            item for item in manifest["partitions"] if item["partition"] == "target"
        )
        digests = [record["record_sha256"] for record in records]
        target["bytes"] = len(target_payload)
        target["sha256"] = sha256(target_payload).hexdigest()
        target["record_set_sha256"] = value_sha256(
            {
                "contract": "cbds.training-record-set",
                "version": "1.0.0",
                "partition": "target",
                "record_sha256s": sorted(digests),
            }
        )
        target["record_sequence_sha256"] = value_sha256(
            {
                "contract": "cbds.training-record-sequence",
                "version": "1.0.0",
                "partition": "target",
                "record_sha256s": digests,
            }
        )
        resign_manifest(self.output, manifest)

        inspected = validate_training_corpus_artifacts(self.output)
        self.assertTrue(inspected["valid"])
        self.assertFalse(inspected["authenticated"])
        with self.assertRaisesRegex(TrainingCorpusError, "does not reproduce"):
            validate_training_corpus_artifacts(
                self.output,
                source_root=self.source,
                require_authenticated=True,
            )


if __name__ == "__main__":
    unittest.main()
