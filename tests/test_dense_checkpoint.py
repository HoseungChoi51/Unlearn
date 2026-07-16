from __future__ import annotations

import copy
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.dense_checkpoint import (  # noqa: E402
    DENSE_CHECKPOINT_EVIDENCE_SCOPE,
    DENSE_CHECKPOINT_RECORD_TYPE,
    DenseCheckpointQualificationError,
    compute_dense_checkpoint_report_sha256,
    inspect_dense_checkpoint,
    validate_dense_checkpoint_report,
    verify_dense_checkpoint_report_sha256,
)
from cbds.model_artifacts import inspect_model_artifact  # noqa: E402


_DTYPE_BITS = {"F4": 4, "U8": 8, "F16": 16, "BF16": 16, "F32": 32}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value) + b"\n")


def _tensor_bytes(dtype: str, shape: list[int]) -> int:
    elements = 1
    for dimension in shape:
        elements *= dimension
    bits = elements * _DTYPE_BITS[dtype]
    if bits % 8:
        raise ValueError("test tensor is not byte-aligned")
    return bits // 8


def _write_safetensors(
    path: Path,
    tensors: list[tuple[str, str, list[int]]],
) -> None:
    header: dict[str, object] = {"__metadata__": {"format": "pt"}}
    offset = 0
    for name, dtype, shape in tensors:
        size = _tensor_bytes(dtype, shape)
        header[name] = {
            "dtype": dtype,
            "shape": shape,
            "data_offsets": [offset, offset + size],
        }
        offset += size
    encoded = _canonical(header)
    path.write_bytes(struct.pack("<Q", len(encoded)) + encoded + b"\0" * offset)


def _config(
    family: str,
    *,
    tied: bool = True,
    layers: int = 2,
) -> dict[str, object]:
    architecture = {
        "qwen2": "Qwen2ForCausalLM",
        "qwen3": "Qwen3ForCausalLM",
        "llama": "LlamaForCausalLM",
    }[family]
    result: dict[str, object] = {
        "architectures": [architecture],
        "model_type": family,
        "hidden_size": 8,
        "intermediate_size": 12,
        "num_hidden_layers": layers,
        "num_attention_heads": 4,
        "num_key_value_heads": 2,
        "vocab_size": 16,
        "tie_word_embeddings": tied,
    }
    if family == "qwen3":
        # Qwen3 permits a query projection wider than the residual stream.
        result["head_dim"] = 4
    return result


def _tensors(
    family: str,
    *,
    tied: bool = True,
    layers: int = 2,
    dtype: str = "F16",
) -> list[tuple[str, str, list[int]]]:
    hidden = 8
    intermediate = 12
    heads = 4
    kv_heads = 2
    head_dim = 4 if family == "qwen3" else 2
    query_width = heads * head_dim
    kv_width = kv_heads * head_dim
    rows: list[tuple[str, str, list[int]]] = [
        ("model.embed_tokens.weight", dtype, [16, hidden]),
        ("model.norm.weight", dtype, [hidden]),
    ]
    if not tied:
        rows.append(("lm_head.weight", dtype, [16, hidden]))
    for layer in range(layers):
        prefix = f"model.layers.{layer}"
        rows.extend(
            [
                (f"{prefix}.input_layernorm.weight", dtype, [hidden]),
                (f"{prefix}.post_attention_layernorm.weight", dtype, [hidden]),
                (f"{prefix}.mlp.gate_proj.weight", dtype, [intermediate, hidden]),
                (f"{prefix}.mlp.up_proj.weight", dtype, [intermediate, hidden]),
                (f"{prefix}.mlp.down_proj.weight", dtype, [hidden, intermediate]),
                (f"{prefix}.self_attn.q_proj.weight", dtype, [query_width, hidden]),
                (f"{prefix}.self_attn.k_proj.weight", dtype, [kv_width, hidden]),
                (f"{prefix}.self_attn.v_proj.weight", dtype, [kv_width, hidden]),
                (f"{prefix}.self_attn.o_proj.weight", dtype, [hidden, query_width]),
            ]
        )
        if family == "qwen2":
            rows.extend(
                [
                    (f"{prefix}.self_attn.q_proj.bias", dtype, [query_width]),
                    (f"{prefix}.self_attn.k_proj.bias", dtype, [kv_width]),
                    (f"{prefix}.self_attn.v_proj.bias", dtype, [kv_width]),
                ]
            )
        if family == "qwen3":
            rows.extend(
                [
                    (f"{prefix}.self_attn.q_norm.weight", dtype, [head_dim]),
                    (f"{prefix}.self_attn.k_norm.weight", dtype, [head_dim]),
                ]
            )
    return sorted(rows, key=lambda row: row[0].encode("utf-8"))


def _make_artifact(
    root: Path,
    family: str,
    *,
    tied: bool = True,
    layers: int = 2,
    dtype: str = "F16",
    config_changes: dict[str, object] | None = None,
    tensor_mutator: object | None = None,
) -> None:
    config = _config(family, tied=tied, layers=layers)
    if config_changes:
        config.update(config_changes)
    tensors = _tensors(family, tied=tied, layers=layers, dtype=dtype)
    if tensor_mutator is not None:
        tensor_mutator(tensors)  # type: ignore[operator]
    _write_json(root / "config.json", config)
    _write_safetensors(root / "model.safetensors", tensors)


def _qualify(root: Path) -> dict[str, object]:
    generic = inspect_model_artifact(root)
    return inspect_dense_checkpoint(
        root,
        expected_inspection_report_sha256=generic["report_sha256"],
    )


def _reseal(report: dict[str, object]) -> dict[str, object]:
    report["report_sha256"] = compute_dense_checkpoint_report_sha256(report)
    return report


class DenseCheckpointHappyPathTests(unittest.TestCase):
    def test_qwen2_qwen3_and_llama_tied_and_untied_are_exact(self) -> None:
        for family in ("qwen2", "qwen3", "llama"):
            for tied in (True, False):
                with self.subTest(family=family, tied=tied), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    _make_artifact(root, family, tied=tied)
                    report = _qualify(root)
                self.assertEqual(report["record_type"], DENSE_CHECKPOINT_RECORD_TYPE)
                self.assertEqual(report["evidence_scope"], DENSE_CHECKPOINT_EVIDENCE_SCOPE)
                self.assertEqual(report["architecture"]["family"], family)  # type: ignore[index]
                self.assertIs(report["architecture"]["tie_word_embeddings"], tied)  # type: ignore[index]
                records = report["tensor_inventory"]["records"]  # type: ignore[index]
                names = {item["name"] for item in records}
                self.assertEqual("lm_head.weight" in names, not tied)
                self.assertEqual(
                    report["tensor_inventory"]["physical_parameter_count"],  # type: ignore[index]
                    sum(item["stored_elements"] for item in records),
                )
                self.assertTrue(verify_dense_checkpoint_report_sha256(report))
                self.assertEqual(
                    report["report_sha256"],
                    compute_dense_checkpoint_report_sha256(report),
                )
                for value in report["authorizations"].values():  # type: ignore[union-attr]
                    self.assertIs(value, False)

    def test_qwen_family_specific_biases_norms_and_gqa_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as qwen2_tmp, tempfile.TemporaryDirectory() as qwen3_tmp:
            qwen2_root = Path(qwen2_tmp)
            qwen3_root = Path(qwen3_tmp)
            _make_artifact(qwen2_root, "qwen2")
            _make_artifact(qwen3_root, "qwen3")
            qwen2 = _qualify(qwen2_root)
            qwen3 = _qualify(qwen3_root)
        qwen2_roles = set(qwen2["operator_bounds"]["tensor_roles"])  # type: ignore[index]
        qwen3_roles = set(qwen3["operator_bounds"]["tensor_roles"])  # type: ignore[index]
        self.assertIn("attention_q_proj_bias", qwen2_roles)
        self.assertNotIn("attention_q_norm", qwen2_roles)
        self.assertIn("attention_q_norm", qwen3_roles)
        self.assertNotIn("attention_q_proj_bias", qwen3_roles)
        qwen3_heads = qwen3["operator_bounds"]["structural"]["attention_head"]  # type: ignore[index]
        self.assertEqual(qwen3_heads["exclusive_upper_bound"], 4)
        self.assertEqual(qwen3_heads["query_heads_per_key_value_head"], 2)
        self.assertIs(qwen3_heads["complete_contiguous_gqa_groups_required"], True)

    def test_factorization_bounds_are_derived_from_stored_out_in_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _make_artifact(root, "qwen3", tied=False)
            report = _qualify(root)
        matrices = {
            item["tensor_name"]: item
            for item in report["operator_bounds"]["factorizable_matrices"]  # type: ignore[index]
        }
        q_proj = matrices["model.layers.0.self_attn.q_proj.weight"]
        self.assertEqual(q_proj["component"], "attention_q_proj")
        self.assertEqual(q_proj["input_dimension"], 8)
        self.assertEqual(q_proj["output_dimension"], 16)
        self.assertEqual(q_proj["layer"], 0)
        self.assertEqual(matrices["lm_head.weight"]["layer"], None)

    def test_report_is_portable_and_defensively_copied(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            _make_artifact(Path(first), "llama")
            _make_artifact(Path(second), "llama")
            left = _qualify(Path(first))
            right = _qualify(Path(second))
        self.assertEqual(left, right)
        copied = validate_dense_checkpoint_report(left)
        self.assertEqual(copied, left)
        copied["architecture"]["hidden_size"] = 999  # type: ignore[index]
        self.assertEqual(left["architecture"]["hidden_size"], 8)  # type: ignore[index]


class DenseCheckpointRejectionTests(unittest.TestCase):
    def assert_rejected(
        self,
        family: str,
        *,
        tied: bool = True,
        dtype: str = "F16",
        config_changes: dict[str, object] | None = None,
        tensor_mutator: object | None = None,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _make_artifact(
                root,
                family,
                tied=tied,
                dtype=dtype,
                config_changes=config_changes,
                tensor_mutator=tensor_mutator,
            )
            generic = inspect_model_artifact(root)
            with self.assertRaises(DenseCheckpointQualificationError):
                inspect_dense_checkpoint(
                    root,
                    expected_inspection_report_sha256=generic["report_sha256"],
                )

    def test_missing_extra_and_wrong_shape_fail(self) -> None:
        def missing(rows: list[tuple[str, str, list[int]]]) -> None:
            rows.pop()

        def extra(rows: list[tuple[str, str, list[int]]]) -> None:
            rows.append(("model.unexpected.weight", "F16", [1]))

        def wrong_shape(rows: list[tuple[str, str, list[int]]]) -> None:
            index = next(
                i for i, row in enumerate(rows) if row[0].endswith("q_proj.weight")
            )
            name, dtype, shape = rows[index]
            rows[index] = (name, dtype, [shape[0] + 1, shape[1]])

        for mutator in (missing, extra, wrong_shape):
            with self.subTest(mutator=mutator.__name__):
                self.assert_rejected("llama", tensor_mutator=mutator)

    def test_family_specific_bias_norm_and_tie_contracts_fail_closed(self) -> None:
        def add_qwen2_norm(rows: list[tuple[str, str, list[int]]]) -> None:
            rows.append(("model.layers.0.self_attn.q_norm.weight", "F16", [2]))

        def remove_qwen2_bias(rows: list[tuple[str, str, list[int]]]) -> None:
            index = next(i for i, row in enumerate(rows) if row[0].endswith("q_proj.bias"))
            rows.pop(index)

        def remove_qwen3_norm(rows: list[tuple[str, str, list[int]]]) -> None:
            index = next(i for i, row in enumerate(rows) if row[0].endswith("q_norm.weight"))
            rows.pop(index)

        def add_tied_head(rows: list[tuple[str, str, list[int]]]) -> None:
            rows.append(("lm_head.weight", "F16", [16, 8]))

        self.assert_rejected("qwen2", tensor_mutator=add_qwen2_norm)
        self.assert_rejected("qwen2", tensor_mutator=remove_qwen2_bias)
        self.assert_rejected("qwen3", tensor_mutator=remove_qwen3_norm)
        self.assert_rejected("llama", tied=True, tensor_mutator=add_tied_head)

    def test_invalid_head_geometry_and_architecture_declarations_fail(self) -> None:
        cases = (
            ("qwen2", {"num_attention_heads": 3}),
            ("qwen2", {"num_key_value_heads": 3}),
            ("qwen3", {"head_dim": None}),
            ("qwen3", {"head_dim": True}),
            ("llama", {"head_dim": 3}),
            ("llama", {"architectures": ["OtherForCausalLM"]}),
            ("llama", {"tie_word_embeddings": 1}),
        )
        for family, changes in cases:
            with self.subTest(family=family, changes=changes):
                self.assert_rejected(family, config_changes=changes)

    def test_packed_integer_mixed_and_low_precision_parameters_fail(self) -> None:
        self.assert_rejected("llama", dtype="U8")
        self.assert_rejected("llama", dtype="F4")

        def mixed(rows: list[tuple[str, str, list[int]]]) -> None:
            name, _dtype, shape = rows[0]
            rows[0] = (name, "F32", shape)

        self.assert_rejected("llama", tensor_mutator=mixed)

    def test_wrong_or_malformed_generic_pin_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _make_artifact(root, "llama")
            with self.assertRaises(DenseCheckpointQualificationError):
                inspect_dense_checkpoint(
                    root,
                    expected_inspection_report_sha256="0" * 64,
                )
            with self.assertRaises(DenseCheckpointQualificationError):
                inspect_dense_checkpoint(
                    root,
                    expected_inspection_report_sha256="not-a-digest",
                )

    def test_report_hash_inventory_authority_and_active_type_tampering_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _make_artifact(root, "qwen3")
            report = _qualify(root)
        variants = []
        changed = copy.deepcopy(report)
        changed["architecture"]["hidden_size"] = 9
        variants.append(changed)
        changed = copy.deepcopy(report)
        changed["tensor_inventory"]["records"][0]["shape"] = [1]
        variants.append(changed)
        changed = copy.deepcopy(report)
        changed["authorizations"]["claim_authorized"] = True
        variants.append(changed)
        changed = copy.deepcopy(report)
        changed["qualification"]["campaign_eligible"] = True
        variants.append(changed)
        for changed in variants:
            self.assertFalse(verify_dense_checkpoint_report_sha256(changed))

        # Recomputing the outer digest cannot legitimize internally
        # inconsistent architecture, inventory, or operator-bound claims.
        changed = copy.deepcopy(report)
        changed["architecture"]["query_heads_per_key_value_head"] = 1
        self.assertFalse(verify_dense_checkpoint_report_sha256(_reseal(changed)))
        changed = copy.deepcopy(report)
        changed["operator_bounds"]["structural"]["attention_head"][  # type: ignore[index]
            "exclusive_upper_bound"
        ] = 999
        self.assertFalse(verify_dense_checkpoint_report_sha256(_reseal(changed)))
        changed = copy.deepcopy(report)
        changed["operator_bounds"]["factorizable_matrices"].pop()  # type: ignore[index]
        self.assertFalse(verify_dense_checkpoint_report_sha256(_reseal(changed)))
        changed = copy.deepcopy(report)
        changed["source_inspection"]["average_stored_bits_per_element"] = 32.0  # type: ignore[index]
        self.assertFalse(verify_dense_checkpoint_report_sha256(_reseal(changed)))
        changed = copy.deepcopy(report)
        changed["source_inspection"]["safetensors_payload_bytes"] += 2  # type: ignore[index,operator]
        self.assertFalse(verify_dense_checkpoint_report_sha256(_reseal(changed)))

        class ActiveDict(dict[str, object]):
            def items(self):  # type: ignore[no-untyped-def]
                raise AssertionError("active mapping hook ran")

        self.assertFalse(verify_dense_checkpoint_report_sha256(ActiveDict(report)))

    def test_validation_does_not_depend_on_python_assert(self) -> None:
        source = (ROOT / "src/cbds/dense_checkpoint.py").read_text(encoding="utf-8")
        self.assertNotIn("assert ", source)
        script = (
            "from cbds.dense_checkpoint import verify_dense_checkpoint_report_sha256 as v;"
            "raise SystemExit(0 if v({}) is False else 9)"
        )
        completed = subprocess.run(
            [sys.executable, "-O", "-c", script],
            cwd=ROOT,
            env={"PYTHONPATH": str(ROOT / "src")},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()
