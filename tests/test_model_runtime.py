from __future__ import annotations

import copy
from contextlib import nullcontext
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.model_artifacts import inspect_model_artifact  # noqa: E402
from cbds.model_runtime import (  # noqa: E402
    MAX_RUNTIME_TOKEN_CAP,
    ModelRuntimeProbeError,
    _RuntimeDependencies,
    account_loaded_model_tensors,
    compute_runtime_report_sha256,
    probe_local_causal_lm,
    validate_runtime_report,
    verify_runtime_report_sha256,
)
import cbds.model_runtime as model_runtime  # noqa: E402
from tests.test_model_artifacts import (  # noqa: E402
    dense_config,
    make_dense_artifact,
    write_json,
)


class FakeStorage:
    def __init__(self, pointer: int, size: int) -> None:
        self.pointer = pointer
        self.size = size

    def data_ptr(self) -> int:
        return self.pointer

    def nbytes(self) -> int:
        return self.size


class FakeTensor:
    def __init__(
        self,
        shape: tuple[int, ...],
        *,
        pointer: int,
        storage: FakeStorage | None = None,
        offset: int = 0,
        dtype: str = "torch.float32",
        element_size: int = 4,
        device: str = "cpu",
        requires_grad: bool = False,
        finite: bool = True,
        contiguous: bool = True,
    ) -> None:
        self.shape = shape
        self.dtype = dtype
        self.device = device
        self.requires_grad = requires_grad
        self.finite = finite
        self.contiguous = contiguous
        self._offset = offset
        self._element_size = element_size
        elements = 1
        for dimension in shape:
            elements *= dimension
        self._elements = elements
        self._storage = storage or FakeStorage(
            pointer, (offset + elements) * element_size
        )

    def numel(self) -> int:
        return self._elements

    def element_size(self) -> int:
        return self._element_size

    def storage_offset(self) -> int:
        return self._offset

    def untyped_storage(self) -> FakeStorage:
        return self._storage

    def is_contiguous(self) -> bool:
        return self.contiguous

    def to(self, device: str) -> FakeTensor:
        self.device = device
        return self


class FakeFinite:
    def __init__(self, value: bool) -> None:
        self.value = value

    def all(self) -> FakeFinite:
        return self

    def item(self) -> bool:
        return self.value


class FakeCuda:
    def __init__(self, *, available: bool = False, count: int = 0) -> None:
        self.available = available
        self.count = count

    def is_available(self) -> bool:
        return self.available

    def device_count(self) -> int:
        return self.count


class FakeTorch:
    __version__ = "2.7.1-fake"

    def __init__(self, *, cuda_available: bool = False, cuda_count: int = 0) -> None:
        self.cuda = FakeCuda(available=cuda_available, count=cuda_count)

    @staticmethod
    def inference_mode() -> object:
        return nullcontext()

    @staticmethod
    def isfinite(tensor: FakeTensor) -> FakeFinite:
        return FakeFinite(tensor.finite)


class FakeTokenizer:
    def __init__(self, tokens: int) -> None:
        self.tokens = tokens
        self.calls: list[tuple[str, dict[str, object]]] = []

    def __call__(self, prompt: str, **kwargs: object) -> dict[str, FakeTensor]:
        self.calls.append((prompt, dict(kwargs)))
        return {
            "input_ids": FakeTensor(
                (1, self.tokens), pointer=10_001, dtype="torch.int64", element_size=8
            ),
            "attention_mask": FakeTensor(
                (1, self.tokens), pointer=10_002, dtype="torch.int64", element_size=8
            ),
        }


class FakeModel:
    def __init__(
        self,
        *,
        finite_logits: bool = True,
        honor_device_move: bool = True,
        logits_shape: tuple[int, ...] | None = None,
        physical_elements: int | None = None,
    ) -> None:
        if physical_elements is None:
            tied_storage = FakeStorage(101, 12 * 4)
            embedding = FakeTensor(
                (3, 4),
                pointer=101,
                storage=tied_storage,
                requires_grad=True,
            )
            # A distinct tensor wrapper over the exact same storage span tests
            # physical rather than merely Python-object de-duplication.
            tied_head = FakeTensor(
                (3, 4),
                pointer=101,
                storage=tied_storage,
                requires_grad=True,
            )
            frozen = FakeTensor((6,), pointer=202, requires_grad=False)
            self.parameters = (
                ("model.embed.weight", embedding),
                ("lm_head.weight", tied_head),
                ("model.layer.weight", frozen),
            )
        else:
            huge = FakeTensor(
                (physical_elements,), pointer=303, requires_grad=True
            )
            self.parameters = (("model.huge.weight", huge),)
        self.buffers = (("model.position_ids", FakeTensor((2,), pointer=404)),)
        self.finite_logits = finite_logits
        self.honor_device_move = honor_device_move
        self.logits_shape = logits_shape
        self.forward_calls = 0
        self.named_parameter_kwargs: list[bool] = []
        self.named_buffer_kwargs: list[bool] = []
        self.forward_kwargs: dict[str, object] | None = None
        self.evaluation_mode = False

    def to(self, device: str) -> FakeModel:
        if self.honor_device_move:
            seen: set[int] = set()
            for _, tensor in (*self.parameters, *self.buffers):
                if id(tensor) not in seen:
                    tensor.to(device)
                    seen.add(id(tensor))
        return self

    def eval(self) -> FakeModel:
        self.evaluation_mode = True
        return self

    def named_parameters(
        self, *, remove_duplicate: bool
    ) -> tuple[tuple[str, FakeTensor], ...]:
        self.named_parameter_kwargs.append(remove_duplicate)
        return self.parameters

    def named_buffers(
        self, *, remove_duplicate: bool
    ) -> tuple[tuple[str, FakeTensor], ...]:
        self.named_buffer_kwargs.append(remove_duplicate)
        return self.buffers

    def __call__(self, **kwargs: object) -> object:
        self.forward_calls += 1
        self.forward_kwargs = dict(kwargs)
        inputs = kwargs["input_ids"]
        assert isinstance(inputs, FakeTensor)
        shape = self.logits_shape or (1, inputs.shape[1], 8)
        return SimpleNamespace(
            logits=FakeTensor(
                shape,
                pointer=505,
                device=inputs.device,
                finite=self.finite_logits,
            )
        )


class TensorInventoryModel:
    """Minimal model interface for adversarial storage-accounting cases."""

    def __init__(
        self,
        parameters: tuple[tuple[str, FakeTensor], ...],
        buffers: tuple[tuple[str, FakeTensor], ...] = (),
    ) -> None:
        self.parameters = parameters
        self.buffers = buffers

    def named_parameters(
        self, *, remove_duplicate: bool
    ) -> tuple[tuple[str, FakeTensor], ...]:
        self.remove_duplicate_parameters = remove_duplicate
        return self.parameters

    def named_buffers(
        self, *, remove_duplicate: bool
    ) -> tuple[tuple[str, FakeTensor], ...]:
        self.remove_duplicate_buffers = remove_duplicate
        return self.buffers


@dataclass
class FakeRuntimeState:
    model: FakeModel
    tokenizer: FakeTokenizer
    model_load_calls: list[tuple[str, dict[str, object]]]
    tokenizer_load_calls: list[tuple[str, dict[str, object]]]


def fake_dependencies(
    *,
    tokens: int = 3,
    model: FakeModel | None = None,
    cuda_available: bool = False,
    cuda_count: int = 0,
    model_error: Exception | None = None,
) -> tuple[_RuntimeDependencies, FakeRuntimeState]:
    resolved_model = FakeModel() if model is None else model
    tokenizer = FakeTokenizer(tokens)
    model_calls: list[tuple[str, dict[str, object]]] = []
    tokenizer_calls: list[tuple[str, dict[str, object]]] = []

    class FakeAutoTokenizer:
        @classmethod
        def from_pretrained(cls, path: str, **kwargs: object) -> FakeTokenizer:
            tokenizer_calls.append((path, dict(kwargs)))
            return tokenizer

    class FakeAutoModelForCausalLM:
        @classmethod
        def from_pretrained(cls, path: str, **kwargs: object) -> FakeModel:
            model_calls.append((path, dict(kwargs)))
            if model_error is not None:
                raise model_error
            return resolved_model

    torch = FakeTorch(cuda_available=cuda_available, cuda_count=cuda_count)
    transformers = SimpleNamespace(
        __version__="4.53.0-fake",
        AutoTokenizer=FakeAutoTokenizer,
        AutoModelForCausalLM=FakeAutoModelForCausalLM,
    )
    return (
        _RuntimeDependencies(torch=torch, transformers=transformers),
        FakeRuntimeState(
            model=resolved_model,
            tokenizer=tokenizer,
            model_load_calls=model_calls,
            tokenizer_load_calls=tokenizer_calls,
        ),
    )


def directory_bytes(root: Path) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in root.iterdir()}


class RuntimeProbeHappyPathTests(unittest.TestCase):
    def test_public_accounting_helper_deduplicates_tied_storage(self) -> None:
        model = FakeModel()
        accounting = account_loaded_model_tensors(model)
        self.assertEqual(accounting["parameters"]["physical_elements"], 18)
        self.assertEqual(accounting["parameters"]["trainable_elements"], 12)
        self.assertEqual(accounting["parameters"]["deduplicated_alias_entries"], 1)
        self.assertEqual(accounting["buffers"]["physical_elements"], 2)
        self.assertEqual(accounting["parameter_devices"], ["cpu"])
        self.assertEqual(accounting["buffer_devices"], ["cpu"])

    def test_accounting_unions_overlapping_and_disjoint_views(self) -> None:
        storage = FakeStorage(901, 12 * 4)
        model = TensorInventoryModel(
            (
                (
                    "overlap.left",
                    FakeTensor(
                        (4,),
                        pointer=901,
                        storage=storage,
                        offset=0,
                        requires_grad=True,
                    ),
                ),
                (
                    "overlap.right",
                    FakeTensor(
                        (4,),
                        pointer=901,
                        storage=storage,
                        offset=2,
                        requires_grad=False,
                    ),
                ),
                (
                    "disjoint",
                    FakeTensor(
                        (2,),
                        pointer=901,
                        storage=storage,
                        offset=8,
                        requires_grad=True,
                    ),
                ),
            )
        )
        parameters = account_loaded_model_tensors(model)["parameters"]
        self.assertEqual(parameters["storage_allocations_referenced"], 1)
        self.assertEqual(parameters["unique_physical_spans"], 3)
        self.assertEqual(parameters["physical_elements"], 8)
        self.assertEqual(parameters["physical_bytes"], 32)
        self.assertEqual(parameters["trainable_elements"], 6)
        self.assertEqual(parameters["trainable_bytes"], 24)

    def test_accounting_rejects_noncontiguous_tensor(self) -> None:
        model = TensorInventoryModel(
            (("noncontiguous", FakeTensor((4,), pointer=902, contiguous=False)),)
        )
        with self.assertRaisesRegex(
            ModelRuntimeProbeError, "tensor_accounting_ambiguous"
        ):
            account_loaded_model_tensors(model)

    def test_accounting_rejects_mixed_dtype_views_of_one_storage(self) -> None:
        storage = FakeStorage(903, 8)
        model = TensorInventoryModel(
            (
                (
                    "float32",
                    FakeTensor(
                        (2,),
                        pointer=903,
                        storage=storage,
                        dtype="torch.float32",
                        element_size=4,
                    ),
                ),
                (
                    "int16",
                    FakeTensor(
                        (4,),
                        pointer=903,
                        storage=storage,
                        dtype="torch.int16",
                        element_size=2,
                    ),
                ),
            )
        )
        with self.assertRaisesRegex(
            ModelRuntimeProbeError, "multiple dtypes"
        ):
            account_loaded_model_tensors(model)

    def test_parameter_and_buffer_shared_storage_use_separate_ledgers(self) -> None:
        storage = FakeStorage(904, 4 * 4)
        parameter = FakeTensor(
            (4,), pointer=904, storage=storage, requires_grad=True
        )
        buffer = FakeTensor((4,), pointer=904, storage=storage)
        accounting = account_loaded_model_tensors(
            TensorInventoryModel((("weight", parameter),), (("cache", buffer),))
        )
        self.assertEqual(accounting["parameters"]["physical_elements"], 4)
        self.assertEqual(accounting["buffers"]["physical_elements"], 4)
        self.assertEqual(
            accounting["parameters"]["accounting_basis"],
            "union_of_contiguous_untyped_storage_byte_spans",
        )

    def test_report_binds_static_runtime_counts_forward_and_loader_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            before = directory_bytes(root)
            dependencies, state = fake_dependencies(tokens=4)
            with mock.patch.object(
                model_runtime,
                "_load_runtime_dependencies",
                return_value=dependencies,
            ):
                report = probe_local_causal_lm(
                    root, "safe local prompt", token_cap=8
                )
            after = directory_bytes(root)
            static = inspect_model_artifact(root)

        self.assertEqual(before, after)
        self.assertTrue(verify_runtime_report_sha256(report))
        self.assertEqual(
            report["report_sha256"], compute_runtime_report_sha256(report)
        )
        self.assertEqual(
            report["static_inspection"]["report_sha256"],
            static["report_sha256"],
        )
        self.assertEqual(
            report["static_inspection"]["architecture_classification"],
            "dense_consistent",
        )
        self.assertEqual(report["parameters"]["named_tensor_entries"], 3)
        self.assertEqual(report["parameters"]["unique_physical_spans"], 2)
        self.assertEqual(report["parameters"]["deduplicated_alias_entries"], 1)
        self.assertEqual(report["parameters"]["physical_elements"], 18)
        self.assertEqual(report["parameters"]["physical_bytes"], 72)
        self.assertEqual(report["parameters"]["trainable_elements"], 12)
        self.assertEqual(report["parameters"]["trainable_bytes"], 48)
        self.assertEqual(
            report["parameters"]["by_dtype"],
            [
                {
                    "dtype": "torch.float32",
                    "physical_elements": 18,
                    "physical_bytes": 72,
                    "trainable_elements": 12,
                    "trainable_bytes": 48,
                }
            ],
        )
        self.assertEqual(report["buffers"]["physical_elements"], 2)
        self.assertEqual(report["buffers"]["physical_bytes"], 8)
        self.assertEqual(report["forward"]["input_ids_shape"], [1, 4])
        self.assertEqual(report["forward"]["logits_shape"], [1, 4, 8])
        self.assertTrue(report["forward"]["logits_finite"])
        self.assertEqual(
            report["dependency_versions"],
            {"torch": "2.7.1-fake", "transformers": "4.53.0-fake"},
        )
        self.assertEqual(report["implementation"]["package_name"], "cbds-research")
        self.assertEqual(
            report["implementation"]["package_version"], model_runtime.__version__
        )
        self.assertEqual(report["implementation"]["module"], "cbds.model_runtime")
        self.assertEqual(
            report["implementation"]["source_sha256"],
            sha256(Path(model_runtime.__file__).read_bytes()).hexdigest(),
        )
        self.assertFalse(report["load_policy"]["os_socket_isolation_provided"])
        self.assertTrue(
            report["claim_qualification"][
                "sub_billion_dense_runtime_qualified"
            ]
        )
        self.assertEqual(state.model.named_parameter_kwargs, [False])
        self.assertEqual(state.model.named_buffer_kwargs, [False])
        self.assertTrue(state.model.evaluation_mode)
        self.assertEqual(state.model.forward_calls, 1)
        self.assertFalse(state.model.forward_kwargs["use_cache"])
        self.assertEqual(
            state.tokenizer.calls,
            [
                (
                    "safe local prompt",
                    {
                        "return_tensors": "pt",
                        "add_special_tokens": True,
                        "truncation": False,
                    },
                )
            ],
        )
        expected_path = str(root.absolute())
        self.assertEqual(
            state.tokenizer_load_calls,
            [
                (
                    expected_path,
                    {"local_files_only": True, "trust_remote_code": False},
                )
            ],
        )
        self.assertEqual(
            state.model_load_calls,
            [
                (
                    expected_path,
                    {
                        "local_files_only": True,
                        "trust_remote_code": False,
                        "use_safetensors": True,
                    },
                )
            ],
        )
        serialized = json.dumps(report, sort_keys=True)
        self.assertNotIn("safe local prompt", serialized)
        self.assertNotIn(expected_path, serialized)

    def test_probe_generated_report_with_only_empty_buffers_validates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            model = FakeModel()
            model.buffers = (
                (
                    "model.empty_buffer",
                    FakeTensor((0,), pointer=909, dtype="torch.float32"),
                ),
            )
            dependencies, _ = fake_dependencies(model=model)
            with mock.patch.object(
                model_runtime,
                "_load_runtime_dependencies",
                return_value=dependencies,
            ):
                report = probe_local_causal_lm(root, "x", token_cap=4)

        self.assertEqual(report["buffers"]["named_tensor_entries"], 1)
        self.assertEqual(report["buffers"]["physical_elements"], 0)
        self.assertEqual(report["buffers"]["physical_bytes"], 0)
        self.assertEqual(report["device_placement"]["buffer_devices"], ["cpu"])
        self.assertEqual(validate_runtime_report(report), report)
        self.assertTrue(verify_runtime_report_sha256(report))

    def test_probe_rejects_dtypes_without_a_portable_size_contract(self) -> None:
        variants = (
            FakeTensor(
                (2,),
                pointer=910,
                dtype="torch.uint16",
                element_size=2,
            ),
            FakeTensor(
                (2,),
                pointer=911,
                dtype="torch.float32",
                element_size=2,
            ),
        )
        for index, buffer in enumerate(variants):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                make_dense_artifact(root)
                model = FakeModel()
                model.buffers = (("model.unportable_buffer", buffer),)
                dependencies, _ = fake_dependencies(model=model)
                with mock.patch.object(
                    model_runtime,
                    "_load_runtime_dependencies",
                    return_value=dependencies,
                ), self.assertRaises(ModelRuntimeProbeError):
                    probe_local_causal_lm(root, "x", token_cap=4)

    def test_report_hash_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            dependencies, _ = fake_dependencies()
            with mock.patch.object(
                model_runtime, "_load_runtime_dependencies", return_value=dependencies
            ):
                report = probe_local_causal_lm(root, "x", token_cap=4)
        tampered = dict(report)
        tampered["runtime_probe_version"] = "tampered"
        self.assertFalse(verify_runtime_report_sha256(tampered))

    def test_portable_runtime_validation_rederives_internal_invariants(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            dependencies, _ = fake_dependencies()
            with mock.patch.object(
                model_runtime, "_load_runtime_dependencies", return_value=dependencies
            ):
                report = probe_local_causal_lm(root, "x", token_cap=4)
        validated = validate_runtime_report(report)
        self.assertEqual(validated, report)
        validated["parameters"]["physical_elements"] = 1
        self.assertNotEqual(validated, report)

        variants = []
        changed = copy.deepcopy(report)
        changed["parameters"]["physical_elements"] += 1
        variants.append(changed)
        changed = copy.deepcopy(report)
        changed["parameters"]["by_dtype"][0]["physical_bytes"] += 1
        variants.append(changed)
        changed = copy.deepcopy(report)
        changed["forward"]["logits_shape"][1] += 1
        variants.append(changed)
        changed = copy.deepcopy(report)
        changed["load_policy"]["trust_remote_code"] = True
        variants.append(changed)
        changed = copy.deepcopy(report)
        changed["claim_qualification"][
            "sub_billion_dense_runtime_qualified"
        ] = False
        variants.append(changed)
        changed = copy.deepcopy(report)
        changed["device_placement"].update(
            {
                "requested": "bogus-device",
                "parameter_devices": ["bogus-device"],
                "buffer_devices": ["bogus-device"],
                "input_device": "bogus-device",
                "logits_device": "bogus-device",
            }
        )
        variants.append(changed)
        for index, changed in enumerate(variants):
            changed["report_sha256"] = compute_runtime_report_sha256(changed)
            with self.subTest(index=index):
                self.assertFalse(verify_runtime_report_sha256(changed))

        class ActiveDict(dict[str, object]):
            def items(self):  # type: ignore[no-untyped-def]
                raise AssertionError("active mapping hook ran")

        self.assertFalse(verify_runtime_report_sha256(ActiveDict(report)))


class StaticTrustBoundaryTests(unittest.TestCase):
    def test_static_inspector_runs_before_dependency_loading_and_hash_tamper_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            real_report = inspect_model_artifact(root)
            tampered = dict(real_report)
            tampered["inspector_version"] = "tampered-without-rehash"
            with mock.patch.object(
                model_runtime, "inspect_model_artifact", return_value=tampered
            ), mock.patch.object(
                model_runtime,
                "_load_runtime_dependencies",
                side_effect=AssertionError("dependencies loaded after bad hash"),
            ):
                with self.assertRaisesRegex(
                    ModelRuntimeProbeError, "static_report_hash_invalid"
                ):
                    probe_local_causal_lm(root, "x", token_cap=4)

    def test_any_auto_map_is_rejected_before_optional_dependencies(self) -> None:
        for auto_map in ({}, {"AutoModelForCausalLM": "custom.Model"}):
            with self.subTest(auto_map=auto_map), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                make_dense_artifact(root)
                write_json(root / "config.json", dense_config(auto_map=auto_map))
                with mock.patch.object(
                    model_runtime,
                    "_load_runtime_dependencies",
                    side_effect=AssertionError("dependencies must not load"),
                ):
                    with self.assertRaisesRegex(
                        ModelRuntimeProbeError, "custom_code_forbidden"
                    ):
                        probe_local_causal_lm(root, "x", token_cap=4)

    def test_local_python_code_is_rejected_before_optional_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            (root / "modeling_custom.py").write_text(
                "raise RuntimeError('must never import')\n", encoding="utf-8"
            )
            with mock.patch.object(
                model_runtime,
                "_load_runtime_dependencies",
                side_effect=AssertionError("dependencies must not load"),
            ):
                with self.assertRaisesRegex(
                    ModelRuntimeProbeError, "custom_code_forbidden"
                ):
                    probe_local_causal_lm(root, "x", token_cap=4)

    def test_static_flat_safetensors_failure_precedes_dependency_loading(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            (root / "pytorch_model.bin").write_bytes(b"unsafe")
            with mock.patch.object(
                model_runtime,
                "_load_runtime_dependencies",
                side_effect=AssertionError("dependencies must not load"),
            ):
                with self.assertRaisesRegex(ValueError, "mixed-format"):
                    probe_local_causal_lm(root, "x", token_cap=4)

    def test_runtime_side_metadata_write_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            dependencies, _ = fake_dependencies()
            loader = dependencies.transformers.AutoModelForCausalLM
            original = loader.from_pretrained

            def mutating_load(path: str, **kwargs: object) -> FakeModel:
                config = root / "config.json"
                metadata = config.stat()
                os.utime(
                    config,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000),
                )
                return original(path, **kwargs)

            with mock.patch.object(
                model_runtime, "_load_runtime_dependencies", return_value=dependencies
            ), mock.patch.object(loader, "from_pretrained", side_effect=mutating_load):
                with self.assertRaisesRegex(ModelRuntimeProbeError, "artifact_changed"):
                    probe_local_causal_lm(root, "x", token_cap=4)


class RuntimeFailureTests(unittest.TestCase):
    def test_nonfinite_logits_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            dependencies, state = fake_dependencies(
                model=FakeModel(finite_logits=False)
            )
            with mock.patch.object(
                model_runtime, "_load_runtime_dependencies", return_value=dependencies
            ):
                with self.assertRaisesRegex(
                    ModelRuntimeProbeError, "nonfinite_logits"
                ):
                    probe_local_causal_lm(root, "x", token_cap=4)
        self.assertEqual(state.model.forward_calls, 1)

    def test_invalid_logit_shape_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            dependencies, _ = fake_dependencies(
                model=FakeModel(logits_shape=(1, 2))
            )
            with mock.patch.object(
                model_runtime, "_load_runtime_dependencies", return_value=dependencies
            ):
                with self.assertRaisesRegex(
                    ModelRuntimeProbeError, "forward_shape_invalid"
                ):
                    probe_local_causal_lm(root, "x", token_cap=4)

    def test_token_overflow_fails_before_forward_without_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            dependencies, state = fake_dependencies(tokens=5)
            with mock.patch.object(
                model_runtime, "_load_runtime_dependencies", return_value=dependencies
            ):
                with self.assertRaisesRegex(
                    ModelRuntimeProbeError, "token_cap_exceeded"
                ):
                    probe_local_causal_lm(root, "overflow", token_cap=4)
        self.assertEqual(state.model.forward_calls, 0)
        self.assertEqual(state.model_load_calls, [])
        self.assertFalse(state.tokenizer.calls[0][1]["truncation"])

    def test_device_mismatch_fails_before_forward(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            dependencies, state = fake_dependencies(
                model=FakeModel(honor_device_move=False),
                cuda_available=True,
                cuda_count=1,
            )
            with mock.patch.object(
                model_runtime, "_load_runtime_dependencies", return_value=dependencies
            ):
                with self.assertRaisesRegex(ModelRuntimeProbeError, "device_mismatch"):
                    probe_local_causal_lm(
                        root, "gpu mismatch", token_cap=4, device="cuda:0"
                    )
        self.assertEqual(state.model.forward_calls, 0)

    def test_missing_dependencies_and_model_load_errors_are_wrapped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            with mock.patch.object(
                model_runtime,
                "_load_runtime_dependencies",
                side_effect=ModelRuntimeProbeError(
                    "dependency_unavailable", "missing"
                ),
            ):
                with self.assertRaisesRegex(
                    ModelRuntimeProbeError, "dependency_unavailable"
                ):
                    probe_local_causal_lm(root, "x", token_cap=4)

            dependencies, _ = fake_dependencies(model_error=OSError("bad weights"))
            with mock.patch.object(
                model_runtime, "_load_runtime_dependencies", return_value=dependencies
            ):
                with self.assertRaisesRegex(ModelRuntimeProbeError, "model_load_failed"):
                    probe_local_causal_lm(root, "x", token_cap=4)

    def test_token_cap_validation_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            for invalid in (True, 0, -1, MAX_RUNTIME_TOKEN_CAP + 1):
                with self.subTest(token_cap=invalid):
                    with self.assertRaisesRegex(
                        ModelRuntimeProbeError, "token_cap_invalid"
                    ):
                        probe_local_causal_lm(
                            root, "x", token_cap=invalid  # type: ignore[arg-type]
                        )


class ClaimBoundaryTests(unittest.TestCase):
    def test_runtime_success_never_upgrades_ambiguous_static_density(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            write_json(
                root / "config.json",
                dense_config(
                    architectures=["MysteryForCausalLM"], model_type="mystery"
                ),
            )
            dependencies, _ = fake_dependencies()
            with mock.patch.object(
                model_runtime, "_load_runtime_dependencies", return_value=dependencies
            ):
                report = probe_local_causal_lm(root, "x", token_cap=4)
        qualification = report["claim_qualification"]
        self.assertEqual(
            qualification["static_density_classification"], "ambiguous"
        )
        self.assertFalse(qualification["sub_billion_dense_runtime_qualified"])
        self.assertFalse(qualification["ambiguous_static_density_upgraded"])

    def test_one_billion_physical_elements_is_not_sub_billion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_dense_artifact(root)
            dependencies, _ = fake_dependencies(
                model=FakeModel(physical_elements=1_000_000_000)
            )
            with mock.patch.object(
                model_runtime, "_load_runtime_dependencies", return_value=dependencies
            ):
                report = probe_local_causal_lm(root, "x", token_cap=4)
        qualification = report["claim_qualification"]
        self.assertEqual(
            qualification["physical_parameter_elements"], 1_000_000_000
        )
        self.assertFalse(
            qualification["physical_parameter_elements_below_one_billion"]
        )
        self.assertFalse(qualification["sub_billion_dense_runtime_qualified"])


if __name__ == "__main__":
    unittest.main()
