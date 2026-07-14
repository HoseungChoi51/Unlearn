from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.model_artifacts import (  # noqa: E402
    InspectionLimits,
    ModelArtifactInspectionError,
    _read_exact_and_hash,
    compute_inspection_report_sha256,
    inspect_model_artifact,
    verify_inspection_report_sha256,
)


TEST_DTYPE_BITS = {"F4": 4, "U8": 8, "F16": 16, "F32": 32}


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def write_json(path: Path, value: object) -> None:
    path.write_bytes(canonical_bytes(value) + b"\n")


def tensor_bytes(dtype: str, shape: list[int]) -> int:
    elements = 1
    for dimension in shape:
        elements *= dimension
    bits = elements * TEST_DTYPE_BITS[dtype]
    if bits % 8:
        raise ValueError("test tensor is not byte aligned")
    return bits // 8


def write_safetensors(
    path: Path,
    tensors: list[tuple[str, str, list[int]]],
    *,
    metadata: dict[str, str] | None = None,
) -> tuple[dict[str, str], int]:
    header: dict[str, object] = {}
    if metadata is not None:
        header["__metadata__"] = metadata
    weight_map: dict[str, str] = {}
    offset = 0
    for name, dtype, shape in tensors:
        size = tensor_bytes(dtype, shape)
        header[name] = {
            "dtype": dtype,
            "shape": shape,
            "data_offsets": [offset, offset + size],
        }
        weight_map[name] = path.name
        offset += size
    header_payload = canonical_bytes(header)
    path.write_bytes(struct.pack("<Q", len(header_payload)) + header_payload + b"\0" * offset)
    return weight_map, offset


def write_raw_safetensors(path: Path, header: object, payload: bytes) -> None:
    header_payload = canonical_bytes(header)
    path.write_bytes(struct.pack("<Q", len(header_payload)) + header_payload + payload)


def dense_config(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "architectures": ["LlamaForCausalLM"],
        "model_type": "llama",
        "hidden_size": 4,
        "intermediate_size": 8,
        "num_hidden_layers": 1,
        "num_attention_heads": 2,
        "num_key_value_heads": 1,
        "vocab_size": 8,
        "tie_word_embeddings": False,
    }
    value.update(updates)
    return value


def dense_tensors() -> list[tuple[str, str, list[int]]]:
    return [
        ("model.embed_tokens.weight", "F16", [8, 4]),
        ("model.layers.0.self_attn.q_proj.weight", "F16", [4, 4]),
        ("model.layers.0.mlp.gate_proj.weight", "F16", [8, 4]),
        ("model.layers.0.mlp.up_proj.weight", "F16", [8, 4]),
        ("model.layers.0.mlp.down_proj.weight", "F16", [4, 8]),
        ("model.layers.0.input_layernorm.weight", "F16", [4]),
        ("lm_head.weight", "F16", [8, 4]),
    ]


def write_tokenizer(root: Path) -> None:
    write_json(
        root / "tokenizer.json",
        {
            "version": "1.0",
            "model": {
                "type": "BPE",
                "vocab": {f"token-{index}": index for index in range(8)},
            },
            "added_tokens": [],
        },
    )


def make_dense_artifact(root: Path, *, tokenizer: bool = True) -> None:
    write_json(root / "config.json", dense_config())
    write_safetensors(root / "model.safetensors", dense_tensors(), metadata={"format": "pt"})
    if tokenizer:
        write_tokenizer(root)


class ModelArtifactHappyPathTests(unittest.TestCase):
    def test_dense_single_file_report_is_content_addressed_and_accounted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            report = inspect_model_artifact(root)

        self.assertEqual(
            report["architecture"]["classification"], "dense_consistent"
        )
        self.assertEqual(
            report["architecture"]["router_tensor_evidence"]["count"], 0
        )
        self.assertFalse(report["architecture"]["ordinary_gate_proj_is_router_evidence"])
        self.assertFalse(
            report["claim_qualification"][
                "physical_network_parameter_count_qualified"
            ]
        )
        weights = report["weights"]
        self.assertEqual(weights["mode"], "single_file")
        self.assertEqual(weights["tensor_count"], 7)
        self.assertEqual(weights["stored_tensor_element_count"], 180)
        self.assertEqual(weights["safetensors_payload_bytes"], 360)
        self.assertEqual(weights["average_stored_bits_per_element"], 16.0)
        self.assertRegex(weights["tensor_layout_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            report["tokenizer"]["locally_inspected_vocab_size"], 8
        )
        self.assertTrue(report["tokenizer"]["matches_config_vocab_size"])

        without_hash = dict(report)
        digest = without_hash.pop("report_sha256")
        self.assertEqual(digest, sha256(canonical_bytes(without_hash)).hexdigest())
        self.assertEqual(digest, compute_inspection_report_sha256(report))
        self.assertTrue(verify_inspection_report_sha256(report))
        tampered = dict(report)
        tampered["inspector_version"] = "tampered"
        self.assertFalse(verify_inspection_report_sha256(tampered))
        self.assertNotIn("artifact_sha256", report)
        self.assertNotEqual(
            report["bundle_manifest_sha256"], report["weight_set_sha256"]
        )

    def test_report_is_portable_across_identical_directories(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            make_dense_artifact(Path(first))
            make_dense_artifact(Path(second))
            first_report = inspect_model_artifact(first)
            second_report = inspect_model_artifact(second)
        self.assertEqual(first_report, second_report)

    def test_weight_bundle_and_tokenizer_hash_domains_are_separate(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_root = Path(first)
            second_root = Path(second)
            make_dense_artifact(first_root)
            make_dense_artifact(second_root)
            tokenizer = json.loads((second_root / "tokenizer.json").read_text())
            tokenizer["model"]["vocab"]["token-0-renamed"] = tokenizer["model"][
                "vocab"
            ].pop("token-0")
            write_json(second_root / "tokenizer.json", tokenizer)
            first_report = inspect_model_artifact(first_root)
            second_report = inspect_model_artifact(second_root)

        self.assertEqual(
            first_report["weight_set_sha256"], second_report["weight_set_sha256"]
        )
        self.assertNotEqual(
            first_report["bundle_manifest_sha256"],
            second_report["bundle_manifest_sha256"],
        )
        self.assertNotEqual(
            first_report["tokenizer"]["tokenizer_set_sha256"],
            second_report["tokenizer"]["tokenizer_set_sha256"],
        )

    def test_prompt_template_and_runtime_tokenizer_companions_are_in_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            # Invalid UTF-8 is intentional: non-JSON sources are byte-hashed,
            # not decoded or accidentally handed to the JSON parser.
            (root / "chat_template.jinja").write_bytes(b"\xff{{ messages }}")
            (root / "sentencepiece.model").write_bytes(b"opaque-spm")
            write_json(root / "tekken.json", {"version": 1, "vocab": []})
            (root / "tokenization_custom.py").write_bytes(b"\xffcustom-code")
            first = inspect_model_artifact(root)

            tokenizer = first["tokenizer"]
            roles = {
                item["path"]: item["role"] for item in tokenizer["source_files"]
            }
            self.assertEqual(roles["chat_template.jinja"], "prompt_template")
            self.assertEqual(roles["sentencepiece.model"], "tokenizer_vocabulary")
            self.assertEqual(roles["tekken.json"], "tokenizer_definition")
            self.assertEqual(
                roles["tokenization_custom.py"], "tokenizer_implementation"
            )
            self.assertEqual(tokenizer["source_file_count"], len(roles))
            self.assertEqual(tokenizer["status"], "json_inspected")

            (root / "chat_template.jinja").write_bytes(b"\xff{{ messages }} changed")
            second = inspect_model_artifact(root)
        self.assertEqual(first["weight_set_sha256"], second["weight_set_sha256"])
        self.assertNotEqual(
            first["tokenizer"]["tokenizer_set_sha256"],
            second["tokenizer"]["tokenizer_set_sha256"],
        )

    def test_tokenizer_identity_report_declares_exact_inclusion_scope(self) -> None:
        expected_exact_names = {
            "added_tokens.json",
            "chat_template.jinja",
            "merges.txt",
            "sentencepiece.bpe.model",
            "sentencepiece.model",
            "special_tokens_map.json",
            "spiece.model",
            "spm.model",
            "tekken.json",
            "tokenizer.json",
            "tokenizer.model",
            "tokenizer_config.json",
            "vocab.json",
            "vocab.txt",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            (root / "README.md").write_text("first", encoding="utf-8")
            first = inspect_model_artifact(root)
            (root / "README.md").write_text("second", encoding="utf-8")
            second = inspect_model_artifact(root)

        tokenizer = first["tokenizer"]
        scope = tokenizer["tokenizer_identity_scope"]
        self.assertEqual(set(scope["recognized_exact_filenames"]), expected_exact_names)
        self.assertEqual(
            scope["recognized_filename_patterns"],
            [r"^tokenization_[A-Za-z0-9_]+\.py$"],
        )
        self.assertEqual(
            scope["record_fields"], ["path", "role", "bytes", "sha256"]
        )
        self.assertIn("non-JSON sources are never parsed as JSON", scope["content_treatment"])
        self.assertIn("top-level", scope["directory_scope"])
        self.assertIn("whole-bundle", scope["other_top_level_files"])
        self.assertEqual(
            first["tokenizer"]["tokenizer_set_sha256"],
            second["tokenizer"]["tokenizer_set_sha256"],
        )
        self.assertNotEqual(
            first["bundle_manifest_sha256"], second["bundle_manifest_sha256"]
        )

    def test_sharded_index_is_bound_to_exact_tensor_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(root / "config.json", dense_config())
            first_tensors = dense_tensors()[:3]
            second_tensors = dense_tensors()[3:]
            first_map, first_size = write_safetensors(
                root / "model-00001-of-00002.safetensors", first_tensors
            )
            second_map, second_size = write_safetensors(
                root / "model-00002-of-00002.safetensors", second_tensors
            )
            write_json(
                root / "model.safetensors.index.json",
                {
                    "metadata": {"total_size": first_size + second_size},
                    "weight_map": {**first_map, **second_map},
                },
            )
            report = inspect_model_artifact(root)
        self.assertEqual(report["weights"]["mode"], "sharded")
        self.assertEqual(report["weights"]["weight_map_entries"], 7)
        self.assertEqual(len(report["weights"]["shards"]), 2)

    def test_binary_tokenizer_is_hashed_without_inventing_vocab_size(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root, tokenizer=False)
            (root / "tokenizer.model").write_bytes(b"opaque sentencepiece data")
            report = inspect_model_artifact(root)
        tokenizer = report["tokenizer"]
        self.assertEqual(tokenizer["status"], "opaque_binary_hashed")
        self.assertRegex(tokenizer["tokenizer_set_sha256"], r"^[0-9a-f]{64}$")
        self.assertIsNone(tokenizer["locally_inspected_vocab_size"])


class ArchitectureClassificationTests(unittest.TestCase):
    def test_explicit_experts_and_router_config_classify_as_moe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(
                root / "config.json",
                dense_config(
                    architectures=["SyntheticMoEForCausalLM"],
                    num_local_experts=2,
                    num_experts_per_tok=1,
                ),
            )
            tensors = dense_tensors() + [
                ("model.layers.0.mlp.experts.0.gate_proj.weight", "F16", [8, 4]),
                ("model.layers.0.mlp.experts.1.gate_proj.weight", "F16", [8, 4]),
                ("model.layers.0.mlp.router.weight", "F16", [2, 4]),
            ]
            write_safetensors(root / "model.safetensors", tensors)
            report = inspect_model_artifact(root)
        self.assertEqual(report["architecture"]["classification"], "moe")
        self.assertGreater(
            report["architecture"]["expert_tensor_evidence"]["count"], 0
        )
        self.assertFalse(
            report["claim_qualification"][
                "physical_network_parameter_count_qualified"
            ]
        )

    def test_common_active_moe_config_markers_cannot_classify_as_dense(self) -> None:
        markers = (
            ("is_moe", True),
            ("use_moe", True),
            ("num_sparse_experts", 4),
            ("moe_num_experts", 4),
            ("shared_expert_intermediate_size", 16),
            ("router_temperature", 1.0),
            ("useMoE", True),
        )
        for key, value in markers:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_json(root / "config.json", dense_config(**{key: value}))
                write_safetensors(root / "model.safetensors", dense_tensors())
                report = inspect_model_artifact(root)
            self.assertEqual(report["architecture"]["classification"], "moe")
            self.assertGreater(
                report["architecture"]["config_moe_evidence"]["count"], 0
            )

    def test_inactive_moe_keys_do_not_create_false_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(
                root / "config.json",
                dense_config(
                    is_moe=False,
                    use_moe=False,
                    num_sparse_experts=0,
                    router_temperature=0,
                    temperature=1.0,
                ),
            )
            write_safetensors(root / "model.safetensors", dense_tensors())
            report = inspect_model_artifact(root)
        self.assertEqual(report["architecture"]["classification"], "dense_consistent")
        self.assertEqual(
            report["architecture"]["config_moe_evidence"]["count"], 0
        )

    def test_long_active_moe_key_is_detected_but_redacted_in_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            secret_key = "SECRET_" + "x" * 4_096 + "_moe_enabled"
            write_json(
                root / "config.json", dense_config(**{secret_key: True})
            )
            write_safetensors(root / "model.safetensors", dense_tensors())
            report = inspect_model_artifact(root)
        self.assertEqual(report["architecture"]["classification"], "moe")
        payload = canonical_bytes(report)
        self.assertNotIn(secret_key.encode(), payload)
        self.assertLess(len(payload), 100_000)

    def test_marker_free_but_incomplete_artifact_remains_ambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(root / "config.json", {"model_type": "custom", "vocab_size": 2})
            write_safetensors(root / "model.safetensors", [("weight", "F16", [2, 2])])
            report = inspect_model_artifact(root)
        self.assertEqual(report["architecture"]["classification"], "ambiguous")
        self.assertFalse(
            report["claim_qualification"]["dense_consistency_evidence_present"]
        )

    def test_shared_expert_namespace_is_moe_but_gate_proj_alone_is_not_router(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(root / "config.json", dense_config())
            write_safetensors(
                root / "model.safetensors",
                dense_tensors()
                + [
                    (
                        "model.layers.0.mlp.shared_expert.gate_proj.weight",
                        "F16",
                        [8, 4],
                    )
                ],
            )
            report = inspect_model_artifact(root)
        self.assertEqual(report["architecture"]["classification"], "moe")
        self.assertEqual(
            report["architecture"]["expert_tensor_evidence"]["count"], 1
        )
        self.assertEqual(
            report["architecture"]["router_tensor_evidence"]["count"], 0
        )

    def test_custom_code_and_rank_three_dense_projection_are_not_dense_consistent(self) -> None:
        with self.subTest(reason="auto_map"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(
                root / "config.json",
                dense_config(auto_map={"AutoModel": "custom.Model"}),
            )
            write_safetensors(root / "model.safetensors", dense_tensors())
            report = inspect_model_artifact(root)
            self.assertEqual(report["architecture"]["classification"], "ambiguous")

        with self.subTest(reason="rank_three"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(root / "config.json", dense_config())
            tensors = dense_tensors()
            tensors[2] = (
                "model.layers.0.mlp.gate_proj.weight",
                "F16",
                [2, 4, 4],
            )
            write_safetensors(root / "model.safetensors", tensors)
            report = inspect_model_artifact(root)
            self.assertEqual(report["architecture"]["classification"], "ambiguous")

    def test_packed_quantization_reports_bits_but_does_not_qualify_logical_count(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(
                root / "config.json",
                dense_config(quantization_config={"quant_method": "synthetic", "bits": 4}),
            )
            tensors = dense_tensors()
            tensors[2] = (
                "model.layers.0.mlp.gate_proj.qweight",
                "U8",
                [8, 4],
            )
            write_safetensors(root / "model.safetensors", tensors)
            report = inspect_model_artifact(root)
        self.assertEqual(
            report["architecture"]["classification"], "dense_consistent"
        )
        self.assertTrue(
            report["quantization"]["logical_count_from_stored_elements_ambiguous"]
        )
        self.assertFalse(
            report["claim_qualification"][
                "physical_network_parameter_count_qualified"
            ]
        )
        self.assertIn(
            "format-specific decoding",
            " ".join(report["claim_qualification"]["caveats"]),
        )


class FilesystemAndJsonBoundaryTests(unittest.TestCase):
    def test_root_and_entries_must_not_be_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "artifact"
            root.mkdir()
            make_dense_artifact(root)
            link = parent / "artifact-link"
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(ModelArtifactInspectionError, "real directory"):
                inspect_model_artifact(link)

            (root / "extra-link").symlink_to(root / "config.json")
            with self.assertRaisesRegex(ModelArtifactInspectionError, "must not be a symlink"):
                inspect_model_artifact(root)

    def test_special_files_subdirectories_and_mixed_weights_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            (root / "nested").mkdir()
            with self.assertRaisesRegex(ModelArtifactInspectionError, "must not be a directory"):
                inspect_model_artifact(root)
            (root / "nested").rmdir()
            (root / "pytorch_model.bin").write_bytes(b"not pickle")
            with self.assertRaisesRegex(ModelArtifactInspectionError, "mixed-format"):
                inspect_model_artifact(root)
            (root / "pytorch_model.bin").unlink()
            if hasattr(os, "mkfifo"):
                os.mkfifo(root / "pipe")
                with self.assertRaisesRegex(ModelArtifactInspectionError, "regular file"):
                    inspect_model_artifact(root)

    def test_common_hugging_face_mixed_weight_families_fail_closed(self) -> None:
        names = (
            "tf_model.h5",
            "flax_model.msgpack",
            "weights.npy",
            "weights.npz",
            "model.ckpt.index",
            "model.ckpt.data-00000-of-00001",
        )
        for name in names:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                make_dense_artifact(root)
                (root / name).write_bytes(b"other weights")
                with self.assertRaisesRegex(ModelArtifactInspectionError, "mixed-format"):
                    inspect_model_artifact(root)

    def test_duplicate_keys_fail_in_config_header_index_and_tokenizer(self) -> None:
        with self.subTest(source="config"):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                make_dense_artifact(root)
                (root / "config.json").write_text(
                    '{"model_type":"llama","model_type":"other"}', encoding="utf-8"
                )
                with self.assertRaisesRegex(ModelArtifactInspectionError, "duplicate JSON"):
                    inspect_model_artifact(root)

        with self.subTest(source="header"):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_json(root / "config.json", dense_config())
                header = (
                    b'{"weight":{"dtype":"F16","shape":[1],"data_offsets":[0,2]},'
                    b'"weight":{"dtype":"F16","shape":[1],"data_offsets":[0,2]}}'
                )
                (root / "model.safetensors").write_bytes(
                    struct.pack("<Q", len(header)) + header + b"\0\0"
                )
                with self.assertRaisesRegex(ModelArtifactInspectionError, "duplicate JSON"):
                    inspect_model_artifact(root)

        with self.subTest(source="tokenizer"):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                make_dense_artifact(root)
                (root / "tokenizer_config.json").write_text(
                    '{"a":1,"a":2}', encoding="utf-8"
                )
                with self.assertRaisesRegex(ModelArtifactInspectionError, "duplicate JSON"):
                    inspect_model_artifact(root)

        with self.subTest(source="index"):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                make_dense_artifact(root, tokenizer=False)
                index = (
                    b'{"metadata":{"total_size":360},"weight_map":{'
                    b'"weight":"model.safetensors",'
                    b'"weight":"model.safetensors"}}'
                )
                (root / "model.safetensors.index.json").write_bytes(index)
                with self.assertRaisesRegex(ModelArtifactInspectionError, "duplicate JSON"):
                    inspect_model_artifact(root)

    def test_lone_surrogate_tensor_name_fails_as_inspection_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(root / "config.json", dense_config())
            header = (
                b'{"\\ud800":{"dtype":"F16","shape":[1],'
                b'"data_offsets":[0,2]}}'
            )
            (root / "model.safetensors").write_bytes(
                struct.pack("<Q", len(header)) + header + b"\0\0"
            )
            with self.assertRaises(ModelArtifactInspectionError):
                inspect_model_artifact(root)

    def test_large_header_and_config_evidence_is_hashed_not_embedded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            secret = "SENSITIVE-EVIDENCE-" + "x" * 4_096
            write_json(
                root / "config.json",
                dense_config(architectures=[f"Llama{secret}"]),
            )
            write_safetensors(
                root / "model.safetensors",
                dense_tensors()
                + [
                    (
                        f"model.layers.0.mlp.shared_expert.{secret}.weight",
                        "F16",
                        [1],
                    )
                ],
                metadata={"private": secret},
            )
            report = inspect_model_artifact(root)
        payload = canonical_bytes(report)
        self.assertNotIn(secret.encode(), payload)
        self.assertLess(len(payload), 100_000)
        shard = report["weights"]["shards"][0]
        self.assertNotIn("metadata", shard)
        self.assertEqual(shard["metadata_entry_count"], 1)
        self.assertRegex(shard["metadata_sha256"], r"^[0-9a-f]{64}$")

    def test_tensor_name_byte_limit_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(root / "config.json", dense_config())
            secret_name = "model.layers.0.SECRET_" + "x" * 100_000
            write_safetensors(
                root / "model.safetensors",
                [(secret_name, "F16", [1])],
            )
            with self.assertRaises(ModelArtifactInspectionError) as caught:
                inspect_model_artifact(
                    root,
                    limits=replace(
                        InspectionLimits(), max_tensor_name_bytes=32
                    ),
                )
        message = str(caught.exception)
        self.assertIn("max_tensor_name_bytes", message)
        self.assertNotIn("SECRET", message)
        self.assertLess(len(message), 1_000)

    def test_duplicate_json_key_errors_are_hash_only_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            secret_key = "SECRET_" + "k" * 100_000
            (root / "config.json").write_text(
                '{"' + secret_key + '":1,"' + secret_key + '":2}',
                encoding="utf-8",
            )
            with self.assertRaises(ModelArtifactInspectionError) as caught:
                inspect_model_artifact(root)
        message = str(caught.exception)
        self.assertIn("duplicate JSON object key", message)
        self.assertNotIn("SECRET", message)
        self.assertLess(len(message), 1_000)

    def test_pathological_float_error_uses_only_token_length_and_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            token = "1e" + "9" * 100_000
            config_payload = canonical_bytes(dense_config())
            (root / "config.json").write_bytes(
                config_payload[:-1] + b',"probe":' + token.encode("ascii") + b"}"
            )
            write_safetensors(root / "model.safetensors", dense_tensors())
            with self.assertRaises(ModelArtifactInspectionError) as caught:
                inspect_model_artifact(root)
        message = str(caught.exception)
        self.assertIn(f"bytes={len(token)}", message)
        self.assertIn(sha256(token.encode("ascii")).hexdigest(), message)
        self.assertNotIn("9" * 100, message)
        self.assertLess(len(message), 1_000)

    def test_layer_count_and_layer_index_resource_limits_fail_closed(self) -> None:
        with self.subTest(source="config"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(root / "config.json", dense_config(num_hidden_layers=3))
            write_safetensors(root / "model.safetensors", dense_tensors())
            with self.assertRaisesRegex(ModelArtifactInspectionError, "max_model_layers"):
                inspect_model_artifact(
                    root,
                    limits=replace(InspectionLimits(), max_model_layers=2),
                )

        with self.subTest(source="tensor"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(root / "config.json", dense_config())
            write_safetensors(
                root / "model.safetensors",
                [(f"model.layers.{'9' * 5_000}.weight", "F16", [1])],
            )
            with self.assertRaisesRegex(ModelArtifactInspectionError, "layer index"):
                inspect_model_artifact(root)


class TokenizerInspectionTests(unittest.TestCase):
    def test_auxiliary_added_token_ids_extend_an_inspected_base_vocab(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root, tokenizer=False)
            write_json(root / "vocab.json", {"a": 0, "b": 1})
            write_json(root / "added_tokens.json", {"<c>": 2})
            write_json(
                root / "tokenizer_config.json",
                {"added_tokens_decoder": {"3": {"content": "<d>"}}},
            )
            report = inspect_model_artifact(root)
        tokenizer = report["tokenizer"]
        self.assertEqual(tokenizer["status"], "json_inspected")
        self.assertEqual(tokenizer["locally_inspected_vocab_size"], 4)
        self.assertEqual(tokenizer["observed_unique_token_ids"], 4)

    def test_invalid_positional_vocab_and_conflicting_ids_are_unresolved(self) -> None:
        cases = (
            {
                "version": "1.0",
                "model": {"type": "Unigram", "vocab": ["not-a-token-score-pair"]},
            },
            {
                "version": "1.0",
                "model": {"type": "BPE", "vocab": {"a": 0, "b": 0}},
            },
            {
                "version": "1.0",
                "model": {"type": "BPE", "vocab": {"a": 0}},
                "added_tokens": [{"id": 0, "content": "different"}],
            },
        )
        for tokenizer_json in cases:
            with self.subTest(
                tokenizer=tokenizer_json
            ), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                make_dense_artifact(root, tokenizer=False)
                write_json(root / "tokenizer.json", tokenizer_json)
                tokenizer = inspect_model_artifact(root)["tokenizer"]
                self.assertEqual(tokenizer["status"], "json_unresolved")
                self.assertIsNone(tokenizer["locally_inspected_vocab_size"])

    def test_pathological_auxiliary_token_id_is_unresolved_without_integer_parse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root, tokenizer=False)
            write_json(root / "vocab.json", {"a": 0})
            write_json(
                root / "tokenizer_config.json",
                {
                    "added_tokens_decoder": {
                        "9" * 5_000: {"content": "too-large"}
                    }
                },
            )
            tokenizer = inspect_model_artifact(root)["tokenizer"]
        self.assertEqual(tokenizer["status"], "json_unresolved")
        self.assertIsNone(tokenizer["locally_inspected_vocab_size"])


class ExactReadBoundaryTests(unittest.TestCase):
    def test_exact_reader_rejects_early_eof_and_growth(self) -> None:
        with self.assertRaisesRegex(ModelArtifactInspectionError, "ended before"):
            _read_exact_and_hash(
                io.BytesIO(b"ab"),
                expected_bytes=3,
                label="short",
                capture=False,
            )
        with self.assertRaisesRegex(ModelArtifactInspectionError, "grew beyond"):
            _read_exact_and_hash(
                io.BytesIO(b"abc"),
                expected_bytes=2,
                label="long",
                capture=False,
            )
        digest, payload = _read_exact_and_hash(
            io.BytesIO(b"abc"),
            expected_bytes=3,
            label="exact",
            capture=True,
        )
        self.assertEqual(digest, sha256(b"abc").hexdigest())
        self.assertEqual(payload, b"abc")


class SafetensorsLayoutMutationTests(unittest.TestCase):
    def artifact_with_header(self, root: Path, header: object, payload: bytes) -> None:
        write_json(root / "config.json", dense_config())
        write_raw_safetensors(root / "model.safetensors", header, payload)

    def test_malformed_and_oversized_headers_fail_before_payload_use(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(root / "config.json", dense_config())
            (root / "model.safetensors").write_bytes(struct.pack("<Q", 1000) + b"{}")
            with self.assertRaisesRegex(ModelArtifactInspectionError, "extends beyond"):
                inspect_model_artifact(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            limits = replace(InspectionLimits(), max_safetensors_header_bytes=16)
            with self.assertRaisesRegex(ModelArtifactInspectionError, "outside the allowed"):
                inspect_model_artifact(root, limits=limits)

    def test_invalid_shapes_spans_and_subbyte_alignment_fail_closed(self) -> None:
        cases = (
            (
                {"w": {"dtype": "F16", "shape": [-1], "data_offsets": [0, 2]}},
                b"\0\0",
                "shape dimensions",
            ),
            (
                {"w": {"dtype": "F16", "shape": [2], "data_offsets": [0, 2]}},
                b"\0\0",
                "byte span",
            ),
            (
                {"w": {"dtype": "F4", "shape": [1], "data_offsets": [0, 0]}},
                b"",
                "not byte aligned",
            ),
        )
        for header, payload, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.artifact_with_header(root, header, payload)
                with self.assertRaisesRegex(ModelArtifactInspectionError, message):
                    inspect_model_artifact(root)

    def test_overlaps_gaps_and_trailing_payload_are_rejected(self) -> None:
        cases = (
            (
                {
                    "a": {"dtype": "F16", "shape": [1], "data_offsets": [0, 2]},
                    "b": {"dtype": "F16", "shape": [1], "data_offsets": [1, 3]},
                },
                b"\0" * 3,
                "overlap",
            ),
            (
                {
                    "a": {"dtype": "F16", "shape": [1], "data_offsets": [0, 2]},
                    "b": {"dtype": "F16", "shape": [1], "data_offsets": [3, 5]},
                },
                b"\0" * 5,
                "unindexed gap",
            ),
            (
                {"a": {"dtype": "F16", "shape": [1], "data_offsets": [0, 2]}},
                b"\0" * 3,
                "not entirely indexed",
            ),
        )
        for header, payload, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.artifact_with_header(root, header, payload)
                with self.assertRaisesRegex(ModelArtifactInspectionError, message):
                    inspect_model_artifact(root)


class ShardAndResourceBoundaryTests(unittest.TestCase):
    def make_shards(self, root: Path) -> tuple[dict[str, str], dict[str, str], int]:
        write_json(root / "config.json", dense_config())
        first, first_size = write_safetensors(
            root / "model-00001-of-00002.safetensors", dense_tensors()[:3]
        )
        second, second_size = write_safetensors(
            root / "model-00002-of-00002.safetensors", dense_tensors()[3:]
        )
        return first, second, first_size + second_size

    def test_missing_wrong_or_unindexed_shard_mappings_fail(self) -> None:
        mutations = ("missing_tensor", "wrong_shard", "wrong_size")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                first, second, total = self.make_shards(root)
                weight_map = {**first, **second}
                if mutation == "missing_tensor":
                    weight_map.pop(next(iter(weight_map)))
                elif mutation == "wrong_shard":
                    name = next(iter(first))
                    weight_map[name] = "model-00002-of-00002.safetensors"
                else:
                    total += 1
                write_json(
                    root / "model.safetensors.index.json",
                    {"metadata": {"total_size": total}, "weight_map": weight_map},
                )
                with self.assertRaises(ModelArtifactInspectionError):
                    inspect_model_artifact(root)

    def test_duplicate_tensor_across_shards_and_missing_index_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(root / "config.json", dense_config())
            repeated = [("model.embed_tokens.weight", "F16", [8, 4])]
            write_safetensors(root / "one.safetensors", repeated)
            write_safetensors(root / "two.safetensors", repeated)
            with self.assertRaisesRegex(ModelArtifactInspectionError, "multiple safetensors"):
                inspect_model_artifact(root)
            write_json(
                root / "model.safetensors.index.json",
                {
                    "metadata": {"total_size": 128},
                    "weight_map": {
                        "model.embed_tokens.weight": "one.safetensors",
                    },
                },
            )
            with self.assertRaisesRegex(ModelArtifactInspectionError, "multiple.*shards"):
                inspect_model_artifact(root)

    def test_resource_limits_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            with self.assertRaisesRegex(ModelArtifactInspectionError, "more than 2"):
                inspect_model_artifact(root, limits=replace(InspectionLimits(), max_files=2))
            with self.assertRaisesRegex(ModelArtifactInspectionError, "max_tensors"):
                inspect_model_artifact(root, limits=replace(InspectionLimits(), max_tensors=6))
            with self.assertRaisesRegex(ModelArtifactInspectionError, "artifact bytes"):
                inspect_model_artifact(
                    root,
                    limits=replace(InspectionLimits(), max_total_artifact_bytes=100),
                )

    def test_limit_configuration_is_strict(self) -> None:
        with self.assertRaisesRegex(ValueError, "positive integer"):
            InspectionLimits(max_files=0)
        with self.assertRaisesRegex(TypeError, "InspectionLimits"):
            inspect_model_artifact("unused", limits={})  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
