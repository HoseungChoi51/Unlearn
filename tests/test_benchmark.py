from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.benchmark import (  # noqa: E402
    BenchmarkConfig,
    BenchmarkValidationError,
    EDGE_CASE_TAGS,
    SPLIT_NAMES,
    SplitCounts,
    canonical_json,
    generate_benchmark,
    load_jsonl,
    prepare_benchmark,
    validate_specs,
)


def tiny_config(seed: int = 73) -> BenchmarkConfig:
    return BenchmarkConfig(
        seed=seed,
        family_size=3,
        static=SplitCounts(6, 3, 2, 2, 3, 2),
        interactive=SplitCounts(4, 2, 1, 1, 2, 1),
    )


class ConfigTests(unittest.TestCase):
    def test_mapping_api_uses_small_defaults_and_partial_overrides(self) -> None:
        config = BenchmarkConfig.from_mapping(
            {"seed": 11, "static": {"train": 7}, "fixture_count": 6}
        )
        self.assertEqual(config.seed, 11)
        self.assertEqual(config.static.train, 7)
        self.assertEqual(
            config.static.operator_selection,
            BenchmarkConfig().static.operator_selection,
        )
        self.assertEqual(config.fixture_count, 6)

    def test_plan_scale_exposes_all_preregistered_counts(self) -> None:
        config = BenchmarkConfig.plan_scale(seed=19)
        self.assertEqual(
            config.static.as_dict(),
            {
                "train": 12_000,
                "operator_selection": 1_000,
                "method_development": 500,
                "shadow_validation": 500,
                "sealed_id": 1_000,
                "sealed_ood": 500,
            },
        )
        self.assertEqual(
            config.interactive.as_dict(),
            {
                "train": 3_000,
                "operator_selection": 500,
                "method_development": 250,
                "shadow_validation": 250,
                "sealed_id": 500,
                "sealed_ood": 250,
            },
        )

    def test_invalid_config_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least 5"):
            BenchmarkConfig(fixture_count=4)
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            BenchmarkConfig(fixture_count=5.0)  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "unknown benchmark config"):
            BenchmarkConfig.from_mapping({"mystery": 1})


class GenerationTests(unittest.TestCase):
    def test_generation_is_deterministic_and_seed_sensitive(self) -> None:
        first = generate_benchmark(tiny_config())
        second = generate_benchmark(tiny_config())
        changed = generate_benchmark(tiny_config(seed=74))
        first_payload = [spec.to_record() for spec in first]
        self.assertEqual(first_payload, [spec.to_record() for spec in second])
        self.assertNotEqual(first_payload, [spec.to_record() for spec in changed])

    def test_specs_are_immutable_unique_and_fixture_complete(self) -> None:
        specs = generate_benchmark(tiny_config())
        self.assertEqual(len({spec.spec_id for spec in specs}), len(specs))
        self.assertEqual(len({spec.graph_hash for spec in specs}), len(specs))
        for spec in specs:
            self.assertGreaterEqual(len(spec.fixtures), 5)
            covered = {
                tag for fixture in spec.fixtures for tag in fixture.edge_case_tags
            }
            self.assertEqual(covered, set(EDGE_CASE_TAGS))
        with self.assertRaises(FrozenInstanceError):
            specs[0].prompt = "mutated"  # type: ignore[misc]

    def test_counts_and_group_level_assignment(self) -> None:
        config = tiny_config()
        specs = generate_benchmark(config)
        for suite_name, expected in (
            ("static", config.static),
            ("interactive", config.interactive),
        ):
            for split in SPLIT_NAMES:
                actual = sum(
                    spec.suite == suite_name and spec.split == split
                    for spec in specs
                )
                self.assertEqual(actual, getattr(expected, split))

        family_splits: dict[tuple[str, str], set[str]] = {}
        signature_splits: dict[tuple[str, str], set[str]] = {}
        for spec in specs:
            family_splits.setdefault(
                (spec.suite, spec.semantic_family), set()
            ).add(spec.split)
            signature_splits.setdefault(
                (spec.suite, spec.semantic_signature), set()
            ).add(spec.split)
        self.assertTrue(any(len(group) >= 3 for group in _family_groups(specs)))
        self.assertTrue(all(len(splits) == 1 for splits in family_splits.values()))
        self.assertTrue(
            all(len(splits) == 1 for splits in signature_splits.values())
        )


def _family_groups(specs: object) -> list[list[object]]:
    groups: dict[tuple[str, str], list[object]] = {}
    for spec in specs:  # type: ignore[union-attr]
        groups.setdefault((spec.suite, spec.semantic_family), []).append(spec)
    return list(groups.values())


class ValidationTests(unittest.TestCase):
    def test_duplicate_ids_and_hashes_are_reported_together(self) -> None:
        specs = list(generate_benchmark(tiny_config()))
        specs[1] = replace(
            specs[1], spec_id=specs[0].spec_id, graph_hash=specs[0].graph_hash
        )
        with self.assertRaises(BenchmarkValidationError) as caught:
            validate_specs(specs)
        message = str(caught.exception)
        self.assertIn("duplicate spec_id", message)
        self.assertIn("duplicate graph_hash", message)
        self.assertIn("does not match graph content", message)

    def test_family_and_signature_split_leakage_are_detected(self) -> None:
        specs = list(generate_benchmark(tiny_config()))
        source = specs[0]
        destination_index = next(
            index
            for index, spec in enumerate(specs)
            if spec.suite == source.suite and spec.split != source.split
        )
        destination = specs[destination_index]
        specs[destination_index] = replace(
            destination,
            semantic_family=source.semantic_family,
            semantic_signature=source.semantic_signature,
        )
        with self.assertRaises(BenchmarkValidationError) as caught:
            validate_specs(specs)
        self.assertIn("semantic family leakage", str(caught.exception))
        self.assertIn("semantic signature leakage", str(caught.exception))

    def test_expected_count_validation_detects_missing_record(self) -> None:
        config = tiny_config()
        specs = generate_benchmark(config)
        with self.assertRaisesRegex(BenchmarkValidationError, "count mismatch"):
            validate_specs(specs[:-1], config=config)


class PreparationTests(unittest.TestCase):
    def test_existing_output_tree_and_member_symlinks_are_never_followed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "dataset"
            (output / "static").mkdir(parents=True)
            victim = root / "victim.txt"
            victim.write_text("do not overwrite", encoding="utf-8")
            (output / "static" / "train.jsonl").symlink_to(victim)
            with self.assertRaises(FileExistsError):
                prepare_benchmark(tiny_config(), output)
            self.assertEqual(victim.read_text(encoding="utf-8"), "do not overwrite")

    def test_smoke_config_has_a_cross_version_golden_dataset_hash(self) -> None:
        config = json.loads(
            (ROOT / "configs" / "benchmark-smoke.json").read_text(encoding="utf-8")
        )
        with tempfile.TemporaryDirectory() as temporary:
            manifest = prepare_benchmark(config, Path(temporary) / "dataset")
        self.assertEqual(
            manifest["dataset_sha256"],
            "eccbef345ecdce2adc3f80990abbd4ae618f933de30baa257076ea836d0ef19f",
        )
        self.assertEqual(
            manifest["generator"],
            {
                "name": "cbds.benchmark",
                "version": "1.0.0",
                "deterministic_sampler": "sha256-counter-rejection-v1",
            },
        )

    def test_prepare_writes_canonical_jsonl_and_hash_manifest(self) -> None:
        config_mapping = tiny_config().as_dict()
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "dataset"
            manifest = prepare_benchmark(config_mapping, output_dir)

            self.assertEqual(len(manifest["files"]), 12)
            self.assertTrue((output_dir / "manifest.json").is_file())
            self.assertTrue((output_dir / "manifest.sha256").is_file())
            for file_record in manifest["files"]:
                path = output_dir / file_record["path"]
                payload = path.read_bytes()
                self.assertEqual(sha256(payload).hexdigest(), file_record["sha256"])
                for line in payload.decode("utf-8").splitlines():
                    self.assertEqual(line, canonical_json(json.loads(line)))

            persisted = json.loads(
                (output_dir / "manifest.json").read_text(encoding="utf-8")
            )
            core = {
                key: value
                for key, value in persisted.items()
                if key not in {"dataset_hash_scope", "dataset_sha256"}
            }
            dataset_digest = sha256(canonical_json(core).encode("utf-8")).hexdigest()
            self.assertEqual(persisted["dataset_sha256"], dataset_digest)
            manifest_digest = sha256(
                (output_dir / "manifest.json").read_bytes()
            ).hexdigest()
            self.assertEqual(
                (output_dir / "manifest.sha256").read_text(encoding="ascii"),
                f"{manifest_digest}  manifest.json\n",
            )

    def test_jsonl_round_trip_preserves_typed_specs(self) -> None:
        config = tiny_config()
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "dataset"
            prepare_benchmark(config, output_dir)
            loaded = load_jsonl(output_dir / "static" / "train.jsonl")
            expected = tuple(
                spec
                for spec in generate_benchmark(config)
                if spec.suite == "static" and spec.split == "train"
            )
            self.assertEqual(loaded, expected)

    def test_repeated_preparation_is_byte_identical(self) -> None:
        config = tiny_config()
        with tempfile.TemporaryDirectory() as first_dir, tempfile.TemporaryDirectory() as second_dir:
            first_output = Path(first_dir) / "dataset"
            second_output = Path(second_dir) / "dataset"
            first_manifest = prepare_benchmark(config, first_output)
            second_manifest = prepare_benchmark(config, second_output)
            self.assertEqual(first_manifest, second_manifest)
            self.assertEqual(
                (first_output / "manifest.json").read_bytes(),
                (second_output / "manifest.json").read_bytes(),
            )


if __name__ == "__main__":
    unittest.main()
