from __future__ import annotations

import csv
from hashlib import sha256
import importlib.util
import json
import math
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.dense_training import (  # noqa: E402
    DenseCanaryConfig,
    DenseTrainingError,
    FP32AdamW,
    TorchDenseRuntime,
    learning_rate_for_update,
    materialize_packed_schedule,
    publish_checkpoint_noreplace,
    run_dense_canary_training,
    validate_published_checkpoint,
)
from cbds.manifests import value_sha256  # noqa: E402
from cbds.token_schedule import prepare_token_schedule  # noqa: E402
from cbds.training_corpus import prepare_training_corpus  # noqa: E402


SCRIPT_SPEC = importlib.util.spec_from_file_location(
    "cbds_dense_sft_canary_script", ROOT / "scripts" / "dense_sft_canary.py"
)
assert SCRIPT_SPEC is not None and SCRIPT_SPEC.loader is not None
DENSE_SCRIPT = importlib.util.module_from_spec(SCRIPT_SPEC)
SCRIPT_SPEC.loader.exec_module(DENSE_SCRIPT)


class TinyTokenizer:
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
            raise AssertionError("special tokens must be disabled")
        if not text:
            return []
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
        del return_offsets_mapping, return_attention_mask
        ids = self.encode(text, add_special_tokens=add_special_tokens)
        marker = "### Response\n"
        response_start = text.find(marker) + len(marker)
        offsets = (
            [(0, len(text))]
            if text.endswith(marker)
            else [(0, response_start), (response_start, len(text))]
        )
        return {"input_ids": ids, "offset_mapping": offsets}

    def save_pretrained(self, destination: Path) -> None:
        (destination / "tokenizer.json").write_text("{}\n", encoding="utf-8")


def corpus_config(source: Path) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "corpus_id": "dense-canary-test-corpus",
        "seed": 17,
        "target_source": {
            "repository": "local/tiny",
            "revision": "a" * 40,
            "relative_path": "train.csv",
            "file_sha256": sha256((source / "train.csv").read_bytes()).hexdigest(),
            "dataset_card_relative_path": "README.md",
            "dataset_card_sha256": sha256((source / "README.md").read_bytes()).hexdigest(),
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


def schedule_config(corpus: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "schedule_id": "dense-canary-test-schedule",
        "seed": 101,
        "source_corpus": {
            "corpus_sha256": corpus["corpus_sha256"],
            "manifest_sha256": corpus["manifest_sha256"],
        },
        "corpus_eligibility": "engineering_only_unverified_not_target_policy_accepted",
        "visible_token_budgets": {"target": 12, "support": 9},
        "sequence_length": 8,
        "tail_selection": {"reserve_visible_tokens": 8, "candidate_occurrences": 24},
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


def fake_model_inspector(model_root: Path) -> dict[str, object]:
    if model_root.name != "model" or not (model_root / "model.safetensors").is_file():
        raise DenseTrainingError("fake exported model layout is invalid")
    return {
        "report_sha256": "a" * 64,
        "bundle_manifest_sha256": "b" * 64,
        "weight_set_sha256": "c" * 64,
        "architecture": {"classification": "dense_consistent"},
        "quantization": {"logical_count_from_stored_elements_ambiguous": False},
        "claim_qualification": {
            "dense_consistent_with_below_one_billion_stored_elements": True
        },
        "weights": {
            "tensor_layout_sha256": "d" * 64,
            "stored_tensor_element_count": 1,
            "safetensors_payload_bytes": 1,
        },
        "config": {"sha256": "e" * 64},
    }


def fake_source_model_binding() -> dict[str, object]:
    identity = {
        "inspection_report_sha256": "1" * 64,
        "bundle_manifest_sha256": "2" * 64,
        "weight_set_sha256": "3" * 64,
        "static_classification": "dense_consistent",
        "tensor_layout_sha256": "4" * 64,
        "stored_tensor_elements": 1,
        "safetensors_payload_bytes": 2,
        "config_sha256": "5" * 64,
    }
    return {
        "initial": dict(identity),
        "after_load": dict(identity),
        "final": dict(identity),
        "stable": True,
    }


class FakeTorch:
    bfloat16 = "bfloat16"
    float32 = "float32"

    class _NoGrad:
        def __enter__(self) -> None:
            return None

        def __exit__(self, *args: object) -> None:
            return None

    @staticmethod
    def no_grad() -> "FakeTorch._NoGrad":
        return FakeTorch._NoGrad()

    @staticmethod
    def zeros_like(tensor: "FakeTensor", *, dtype: str) -> "FakeTensor":
        return FakeTensor(0.0, dtype=dtype)


class FakeTensor:
    def __init__(self, value: float, *, dtype: str = FakeTorch.bfloat16) -> None:
        self.value = float(value)
        self.dtype = dtype
        self.grad: FakeTensor | None = None
        self.requires_grad = True
        self.is_sparse = False

    def numel(self) -> int:
        return 1

    def detach(self) -> "FakeTensor":
        return FakeTensor(self.value, dtype=self.dtype)

    def to(self, *, dtype: str) -> "FakeTensor":
        return FakeTensor(self.value, dtype=dtype)

    def mul_(self, value: float) -> "FakeTensor":
        self.value *= value
        return self

    def add_(self, other: "FakeTensor | float", *, alpha: float = 1.0) -> "FakeTensor":
        self.value += (other.value if isinstance(other, FakeTensor) else other) * alpha
        return self

    def addcmul_(
        self, first: "FakeTensor", second: "FakeTensor", *, value: float
    ) -> "FakeTensor":
        self.value += first.value * second.value * value
        return self

    def sqrt(self) -> "FakeTensor":
        return FakeTensor(math.sqrt(self.value), dtype=self.dtype)

    def div_(self, value: float) -> "FakeTensor":
        self.value /= value
        return self

    def div(self, other: "FakeTensor") -> "FakeTensor":
        return FakeTensor(self.value / other.value, dtype=self.dtype)


class FakeModel:
    def __init__(self) -> None:
        self.weight = FakeTensor(1.0)
        self.calls: list[tuple[int, ...]] = []

    def parameters(self) -> tuple[FakeTensor, ...]:
        return (self.weight,)


class FakeRuntime:
    """CPU-free runtime that records the exact normalization denominators."""

    def __init__(self, torch: FakeTorch, model: FakeModel) -> None:
        self.torch = torch
        self.model = model
        self.divisors: list[int] = []
        self.learning_rates: list[float] = []
        self.zero_calls = 0

    def zero_grad(self) -> None:
        self.zero_calls += 1

    def backward_loss_sum(self, rows: object) -> float:
        resolved = tuple(rows)  # type: ignore[arg-type]
        self.model.calls.append(tuple(row.sequence_index for row in resolved))
        return 2.0 * sum(row.supervised_tokens for row in resolved)

    def divide_gradients(self, supervised_tokens: int) -> None:
        self.divisors.append(supervised_tokens)

    def clip_grad_norm(self, maximum: float) -> float:
        self.assert_maximum = maximum
        return 0.75

    def optimizer_step(self, learning_rate: float) -> None:
        self.learning_rates.append(learning_rate)

    def estimate_step_flops(self, token_slots: int) -> int:
        return 6 * self.model.weight.numel() * token_slots


class DenseSFTCanaryTests(unittest.TestCase):
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
        corpus = prepare_training_corpus(
            corpus_config(self.source), source_root=self.source, output_dir=self.corpus_dir
        )
        self.tokenizer_dir = self.root / "tokenizer"
        self.tokenizer_dir.mkdir()
        (self.tokenizer_dir / "config.json").write_text(
            json.dumps(
                {"model_type": "tiny", "vocab_size": 32, "tie_word_embeddings": True},
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        (self.tokenizer_dir / "tokenizer_config.json").write_text(
            '{"tokenizer_class":"TinyTokenizer"}', encoding="utf-8"
        )
        (self.tokenizer_dir / "tokenizer.json").write_text(
            '{"version":"test"}', encoding="utf-8"
        )
        self.schedule_dir = self.root / "schedule"
        self.prepared = prepare_token_schedule(
            schedule_config(corpus),
            corpus_dir=self.corpus_dir,
            corpus_source_root=self.source,
            tokenizer_root=self.tokenizer_dir,
            output_dir=self.schedule_dir,
            tokenizer=TinyTokenizer(),
            model_embedding_rows=32,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def materialize(self):
        return materialize_packed_schedule(
            self.schedule_dir,
            corpus_dir=self.corpus_dir,
            corpus_source_root=self.source,
            tokenizer_root=self.tokenizer_dir,
            tokenizer=TinyTokenizer(),
            model_embedding_rows=32,
            expected_schedule_sha256=self.prepared["schedule_sha256"],
            expected_manifest_sha256=self.prepared["manifest_sha256"],
        )

    def test_source_replay_reconstructs_exact_response_eos_packed_tensors(self) -> None:
        schedule = self.materialize()
        self.assertEqual(schedule.total_visible_tokens, 21)
        self.assertEqual(schedule.total_supervised_tokens, 14)
        self.assertEqual(len(schedule.sequences), 4)
        for row in schedule.sequences:
            self.assertEqual(len(row.input_ids), 8)
            self.assertEqual(len(row.labels), 8)
            self.assertEqual(sum(row.attention_mask), row.visible_tokens)
            self.assertEqual(
                sum(label != -100 for label in row.labels), row.supervised_tokens
            )
            self.assertEqual(row.position_ids, tuple(range(8)))
        self.assertFalse(schedule.identity["target_policy_accepted"])
        self.assertFalse(schedule.identity["claim_authorized"])

    def test_accumulation_uses_actual_supervised_tokens_in_final_partial_update(self) -> None:
        schedule = self.materialize()
        fake_model = FakeModel()
        runtime = FakeRuntime(FakeTorch(), fake_model)
        config = DenseCanaryConfig(
            base_learning_rate=1e-3,
            microbatch_sequences=1,
            accumulation_microbatches=3,
            expected_total_visible_tokens=21,
            seed=9,
        )
        ledger, summary = run_dense_canary_training(
            schedule,
            config,
            runtime,
            execution_binding={"runtime": "fake", "flop_formula": "6N_slots"},
        )
        self.assertEqual(runtime.divisors, [12, 2])
        self.assertEqual([row["supervised_tokens"] for row in ledger], [12, 2])
        self.assertEqual([row["visible_tokens"] for row in ledger], [18, 3])
        self.assertEqual([row["loss_mean_per_supervised_token"] for row in ledger], [2.0, 2.0])
        self.assertEqual(summary["visible_tokens"], 21)
        self.assertEqual(summary["supervised_tokens"], 14)
        self.assertFalse(summary["campaign_eligible"])
        self.assertFalse(summary["model_selection_eligible"])
        self.assertFalse(summary["claim_eligible"])
        previous = ledger[0]["previous_step_sha256"]
        for row in ledger:
            self.assertEqual(row["previous_step_sha256"], previous)
            unsigned = dict(row)
            claimed = unsigned.pop("step_sha256")
            self.assertEqual(value_sha256(unsigned), claimed)
            previous = claimed
        self.assertEqual(summary["ledger_final_step_sha256"], previous)

    def test_visible_token_mismatch_fails_without_a_runtime_step(self) -> None:
        schedule = self.materialize()
        runtime = FakeRuntime(FakeTorch(), FakeModel())
        with self.assertRaisesRegex(DenseTrainingError, "truncation is forbidden"):
            run_dense_canary_training(
                schedule,
                DenseCanaryConfig(
                    base_learning_rate=1e-3,
                    microbatch_sequences=1,
                    accumulation_microbatches=1,
                    expected_total_visible_tokens=20,
                    seed=1,
                ),
                runtime,
                execution_binding={"runtime": "fake"},
            )
        self.assertEqual(runtime.zero_calls, 0)

    def test_learning_rate_is_five_percent_warmup_then_cosine_per_update(self) -> None:
        base = 2e-3
        self.assertEqual(learning_rate_for_update(base, 1, 40), base / 2)
        self.assertEqual(learning_rate_for_update(base, 2, 40), base)
        self.assertAlmostEqual(
            learning_rate_for_update(base, 21, 40),
            base * 0.5 * (1 + math.cos(math.pi * 19 / 38)),
        )
        self.assertEqual(learning_rate_for_update(base, 40, 40), 0.0)

    def test_fake_torch_adamw_uses_fp32_moments_and_full_model_gate(self) -> None:
        torch = FakeTorch()
        model = FakeModel()
        runtime = TorchDenseRuntime(torch, model, "fake-device")
        model.weight.grad = FakeTensor(0.25)
        optimizer = FP32AdamW(torch, model.parameters())
        optimizer.step(1e-3)
        self.assertEqual(optimizer.state_dtypes(), {FakeTorch.float32})
        self.assertLess(model.weight.value, 1.0)
        self.assertTrue(runtime.runtime_record()["full_model_trainable"])
        model.weight.dtype = "float16"
        with self.assertRaisesRegex(DenseTrainingError, "BF16"):
            TorchDenseRuntime(torch, model, "fake-device")

    def test_model_loader_is_local_only_remote_code_off_and_safetensors_only(self) -> None:
        captured: dict[str, object] = {}
        sentinel = object()

        class FakeAutoModel:
            @classmethod
            def from_pretrained(cls, path: Path, **kwargs: object) -> object:
                captured["path"] = path
                captured.update(kwargs)
                return sentinel

        loaded = DENSE_SCRIPT._load_local_bf16_model(
            FakeAutoModel, FakeTorch(), Path("/already/local/model")
        )
        self.assertIs(loaded, sentinel)
        self.assertEqual(captured["path"], Path("/already/local/model"))
        self.assertIs(captured["local_files_only"], True)
        self.assertIs(captured["trust_remote_code"], False)
        self.assertIs(captured["use_safetensors"], True)
        self.assertEqual(captured["torch_dtype"], FakeTorch.bfloat16)

    def test_engineering_measurements_are_descriptive_and_nonselecting(self) -> None:
        class FakeCuda:
            @staticmethod
            def max_memory_allocated(device: int) -> int:
                self.assertEqual(device, 0)
                return 123

            @staticmethod
            def max_memory_reserved(device: int) -> int:
                self.assertEqual(device, 0)
                return 456

        class MeasurementTorch:
            cuda = FakeCuda()

        record = DENSE_SCRIPT._engineering_measurements(
            {"optimizer_updates": 4, "visible_tokens": 80, "supervised_tokens": 20},
            2.0,
            MeasurementTorch(),
        )
        self.assertEqual(record["visible_tokens_per_second"], 40.0)
        self.assertEqual(record["supervised_tokens_per_second"], 10.0)
        self.assertEqual(record["milliseconds_per_optimizer_update"], 500.0)
        self.assertEqual(record["peak_cuda_memory_allocated_bytes"], 123)
        self.assertEqual(record["peak_cuda_memory_reserved_bytes"], 456)
        self.assertFalse(record["trajectory_determinism_guaranteed"])
        self.assertFalse(record["campaign_eligible"])
        self.assertFalse(record["model_selection_eligible"])
        self.assertFalse(record["claim_eligible"])
        self.assertTrue(record["selection_use_prohibited"])

    def test_checkpoint_publication_is_no_replace_and_never_claim_eligible(self) -> None:
        schedule = self.materialize()
        runtime = FakeRuntime(FakeTorch(), FakeModel())
        ledger, summary = run_dense_canary_training(
            schedule,
            DenseCanaryConfig(1e-3, 2, 2, 21, 3),
            runtime,
            execution_binding={"runtime": "fake"},
        )
        output = self.root / "checkpoint"

        def exporter(staging: Path) -> None:
            (staging / "model.safetensors").write_bytes(b"fake-safe-tensors")

        completion = publish_checkpoint_noreplace(
            output,
            ledger_records=ledger,
            completion_base={
                "training_summary": summary,
                "source_model": fake_source_model_binding(),
                "source_schedule": dict(schedule.identity),
                "campaign_eligible": False,
                "model_selection_eligible": False,
                "claim_eligible": False,
            },
            exporter=exporter,
            tensor_hasher=lambda _: sha256(b"logical fake tensor").hexdigest(),
            model_inspector=fake_model_inspector,
        )
        self.assertTrue((output / "completion.json").is_file())
        self.assertTrue((output / "step-ledger.jsonl").is_file())
        self.assertTrue((output / "model" / "model.safetensors").is_file())
        self.assertFalse((output / "model.safetensors").exists())
        self.assertTrue(
            any(
                item["path"].startswith("model/")
                for item in completion["checkpoint_files"]
            )
        )
        self.assertFalse(completion["campaign_eligible"])
        self.assertFalse(completion["model_selection_eligible"])
        self.assertFalse(completion["claim_eligible"])
        verified = validate_published_checkpoint(
            output,
            tensor_hasher=lambda _: sha256(b"logical fake tensor").hexdigest(),
            expected_model_inspection_sha256="1" * 64,
            expected_schedule_sha256=self.prepared["schedule_sha256"],
            expected_schedule_manifest_sha256=self.prepared["manifest_sha256"],
            model_inspector=fake_model_inspector,
        )
        self.assertTrue(verified["valid"])
        self.assertFalse(verified["claim_eligible"])

        def drifted_model_inspector(model_root: Path) -> dict[str, object]:
            report = fake_model_inspector(model_root)
            report["report_sha256"] = "f" * 64
            return report

        with self.assertRaisesRegex(DenseTrainingError, "identity does not reproduce"):
            validate_published_checkpoint(
                output, model_inspector=drifted_model_inspector
            )
        before = {
            str(item.relative_to(output)): item.read_bytes()
            for item in output.rglob("*")
            if item.is_file()
        }
        with self.assertRaisesRegex(DenseTrainingError, "already exists"):
            publish_checkpoint_noreplace(
                output,
                ledger_records=ledger,
                completion_base={
                    "campaign_eligible": False,
                    "model_selection_eligible": False,
                    "claim_eligible": False,
                },
                exporter=exporter,
                tensor_hasher=lambda _: "0" * 64,
            )
        self.assertEqual(
            before,
            {
                str(item.relative_to(output)): item.read_bytes()
                for item in output.rglob("*")
                if item.is_file()
            },
        )

        (output / "unexpected.bin").write_bytes(b"undeclared")
        with self.assertRaisesRegex(DenseTrainingError, "must contain only"):
            validate_published_checkpoint(output, model_inspector=fake_model_inspector)

    def test_completion_eligibility_reseal_and_ledger_byte_tamper_fail_closed(self) -> None:
        schedule = self.materialize()
        runtime = FakeRuntime(FakeTorch(), FakeModel())
        ledger, summary = run_dense_canary_training(
            schedule,
            DenseCanaryConfig(1e-3, 2, 2, 21, 3),
            runtime,
            execution_binding={"runtime": "fake"},
        )

        def publish(name: str) -> Path:
            output = self.root / name
            publish_checkpoint_noreplace(
                output,
                ledger_records=ledger,
                completion_base={
                    "training_summary": summary,
                    "source_model": fake_source_model_binding(),
                    "source_schedule": dict(schedule.identity),
                    "campaign_eligible": False,
                    "model_selection_eligible": False,
                    "claim_eligible": False,
                },
                exporter=lambda staging: (staging / "model.safetensors").write_bytes(
                    b"fake-safe-tensors"
                ),
                tensor_hasher=lambda _: sha256(b"logical fake tensor").hexdigest(),
                model_inspector=fake_model_inspector,
            )
            return output

        resealed = publish("resealed-eligibility")
        completion_path = resealed / "completion.json"
        completion = json.loads(completion_path.read_text(encoding="utf-8"))
        completion["claim_eligible"] = True
        unsigned = dict(completion)
        unsigned.pop("completion_sha256")
        completion["completion_sha256"] = value_sha256(unsigned)
        completion_path.write_text(
            json.dumps(completion, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(DenseTrainingError, "claim_eligible must remain false"):
            validate_published_checkpoint(resealed, model_inspector=fake_model_inspector)

        ledger_tamper = publish("ledger-byte-tamper")
        ledger_path = ledger_tamper / "step-ledger.jsonl"
        payload = ledger_path.read_bytes()
        ledger_path.write_bytes(payload.replace(b'"visible_tokens":', b'"visible_tokens" :', 1))
        with self.assertRaisesRegex(DenseTrainingError, "inventory differs"):
            validate_published_checkpoint(
                ledger_tamper, model_inspector=fake_model_inspector
            )

        clean = publish("wrong-external-pin")
        with self.assertRaisesRegex(DenseTrainingError, "external pin"):
            validate_published_checkpoint(
                clean,
                expected_schedule_sha256="0" * 64,
                model_inspector=fake_model_inspector,
            )

    def test_inconsistent_tensor_hasher_prevents_atomic_publication(self) -> None:
        schedule = self.materialize()
        ledger, summary = run_dense_canary_training(
            schedule,
            DenseCanaryConfig(1e-3, 2, 2, 21, 3),
            FakeRuntime(FakeTorch(), FakeModel()),
            execution_binding={"runtime": "fake"},
        )
        output = self.root / "must-not-publish"
        returned_hashes = iter(("0" * 64, "1" * 64))
        with self.assertRaisesRegex(DenseTrainingError, "tensor hash does not reproduce"):
            publish_checkpoint_noreplace(
                output,
                ledger_records=ledger,
                completion_base={
                    "training_summary": summary,
                    "source_model": fake_source_model_binding(),
                    "source_schedule": dict(schedule.identity),
                    "campaign_eligible": False,
                    "model_selection_eligible": False,
                    "claim_eligible": False,
                },
                exporter=lambda model_root: (
                    model_root / "model.safetensors"
                ).write_bytes(b"fake-safe-tensors"),
                tensor_hasher=lambda _: next(returned_hashes),
                model_inspector=fake_model_inspector,
            )
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
