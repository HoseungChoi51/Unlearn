from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "gpu_microfit.py"
SPEC = importlib.util.spec_from_file_location("cbds_gpu_microfit", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
gpu_microfit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gpu_microfit)


class FakeStorage:
    def data_ptr(self) -> int:
        return 1001

    def nbytes(self) -> int:
        return 16


class FakeParameter:
    dtype = "torch.bfloat16"
    device = "cuda:0"
    requires_grad = True

    def numel(self) -> int:
        return 8

    def element_size(self) -> int:
        return 2

    def storage_offset(self) -> int:
        return 0

    def untyped_storage(self) -> FakeStorage:
        return FakeStorage()

    def is_contiguous(self) -> bool:
        return True


class FakeScalar:
    def __init__(self, value: float) -> None:
        self.value = value
        self.backward_calls = 0

    def numel(self) -> int:
        return 1

    def backward(self) -> None:
        self.backward_calls += 1

    def detach(self) -> FakeScalar:
        return self

    def cpu(self) -> FakeScalar:
        return self

    def __float__(self) -> float:
        return self.value


class FakeInputTensor:
    def __init__(self, shape: tuple[int, int], payload: bytes) -> None:
        self.shape = shape
        self.payload = payload
        self.device = "cpu"

    def numpy(self) -> FakeInputTensor:
        return self

    def tobytes(self, *, order: str) -> bytes:
        assert order == "C"
        return self.payload

    def to(self, *, device: str, non_blocking: bool) -> FakeInputTensor:
        assert non_blocking is False
        self.device = str(device)
        return self

    def clone(self) -> FakeInputTensor:
        cloned = FakeInputTensor(self.shape, self.payload)
        cloned.device = self.device
        return cloned


class FakeGenerator:
    def __init__(self, *, device: str) -> None:
        self.device = device
        self.seed: int | None = None

    def manual_seed(self, seed: int) -> FakeGenerator:
        self.seed = seed
        return self


class FakeTrainingModel:
    def __init__(self) -> None:
        self.config = SimpleNamespace(vocab_size=32, use_cache=True)
        self.parameter = FakeParameter()
        self.training = False
        self.checkpointing = False
        self.forward_calls = 0

    def to(self, device: str) -> FakeTrainingModel:
        self.parameter.device = str(device)
        return self

    def train(self) -> FakeTrainingModel:
        self.training = True
        return self

    def gradient_checkpointing_enable(self) -> None:
        self.checkpointing = True

    def parameters(self) -> tuple[FakeParameter, ...]:
        return (self.parameter,)

    def named_parameters(
        self, *, remove_duplicate: bool
    ) -> tuple[tuple[str, FakeParameter], ...]:
        assert remove_duplicate is False
        return (("weight", self.parameter),)

    def named_buffers(
        self, *, remove_duplicate: bool
    ) -> tuple[tuple[str, FakeParameter], ...]:
        assert remove_duplicate is False
        return ()

    def __call__(self, **kwargs: object) -> object:
        self.forward_calls += 1
        assert kwargs["use_cache"] is False
        return SimpleNamespace(loss=FakeScalar(2.0 - 0.1 * self.forward_calls))


class FakeOptimizer:
    def __init__(self, parameters: object, **kwargs: object) -> None:
        self.parameters = tuple(parameters)  # type: ignore[arg-type]
        self.kwargs = kwargs
        self.zero_grad_calls: list[bool] = []
        self.steps = 0

    def zero_grad(self, *, set_to_none: bool) -> None:
        self.zero_grad_calls.append(set_to_none)

    def step(self) -> None:
        self.steps += 1


class FakeOptim:
    def __init__(self) -> None:
        self.instances: list[FakeOptimizer] = []

    def AdamW(self, parameters: object, **kwargs: object) -> FakeOptimizer:
        optimizer = FakeOptimizer(parameters, **kwargs)
        self.instances.append(optimizer)
        return optimizer


class FakeCuda:
    def __init__(self) -> None:
        self.manual_seeds: list[int] = []
        self.synchronizations = 0

    def is_available(self) -> bool:
        return True

    def is_bf16_supported(self) -> bool:
        return True

    def manual_seed_all(self, seed: int) -> None:
        self.manual_seeds.append(seed)

    def set_device(self, device: int) -> None:
        assert device == 0

    def empty_cache(self) -> None:
        return None

    def synchronize(self) -> None:
        self.synchronizations += 1

    def reset_peak_memory_stats(self) -> None:
        return None

    def current_device(self) -> int:
        return 0

    def get_device_properties(self, device: int) -> object:
        assert device == 0
        return SimpleNamespace(
            name="Fake CUDA",
            total_memory=32 * 1024**3,
            major=12,
            minor=0,
        )

    def max_memory_allocated(self, device: int) -> int:
        assert device == 0
        return 1024

    def max_memory_reserved(self, device: int) -> int:
        assert device == 0
        return 2048


class FakeTorch:
    __version__ = "2.4.0-fake"
    bfloat16 = "torch.bfloat16"
    long = "torch.int64"

    def __init__(self) -> None:
        self.cuda = FakeCuda()
        self.backends = SimpleNamespace(
            cuda=SimpleNamespace(matmul=SimpleNamespace(allow_tf32=True)),
            cudnn=SimpleNamespace(allow_tf32=True),
        )
        self.optim = FakeOptim()
        self.nn = SimpleNamespace(
            utils=SimpleNamespace(clip_grad_norm_=lambda parameters, maximum: 1.0)
        )
        self.version = SimpleNamespace(cuda="12.8-fake")
        self.manual_seeds: list[int] = []

    def manual_seed(self, seed: int) -> None:
        self.manual_seeds.append(seed)

    @staticmethod
    def device(kind: str, index: int) -> str:
        return f"{kind}:{index}"

    @staticmethod
    def Generator(*, device: str) -> FakeGenerator:
        return FakeGenerator(device=device)

    @staticmethod
    def randint(
        start: int,
        stop: int,
        shape: tuple[int, int],
        **kwargs: object,
    ) -> FakeInputTensor:
        assert start == 0
        assert stop > 1
        assert kwargs["device"] == "cpu"
        payload = bytes((index % stop for index in range(shape[0] * shape[1])))
        return FakeInputTensor(shape, payload)

    @staticmethod
    def ones_like(value: FakeInputTensor) -> FakeInputTensor:
        result = FakeInputTensor(value.shape, b"\x01" * len(value.payload))
        result.device = value.device
        return result

    @staticmethod
    def isfinite(value: object) -> bool:
        return True


class FakeAutoModelForCausalLM:
    model = FakeTrainingModel()
    calls: list[tuple[Path, dict[str, object]]] = []

    @classmethod
    def reset(cls) -> None:
        cls.model = FakeTrainingModel()
        cls.calls = []

    @classmethod
    def from_pretrained(cls, path: Path, **kwargs: object) -> FakeTrainingModel:
        cls.calls.append((path, dict(kwargs)))
        return cls.model


def fake_stack() -> tuple[FakeTorch, object, type[FakeAutoModelForCausalLM]]:
    FakeAutoModelForCausalLM.reset()
    torch = FakeTorch()
    transformers = SimpleNamespace(__version__="4.45.0-fake")
    return torch, transformers, FakeAutoModelForCausalLM


def static_report(report_sha256: str = "a" * 64) -> dict[str, object]:
    return {
        "report_sha256": report_sha256,
        "bundle_manifest_sha256": "b" * 64,
        "weight_set_sha256": "c" * 64,
        "architecture": {"classification": "dense_consistent"},
        "claim_qualification": {
            "stored_tensor_element_count_below_one_billion": True
        },
        "weights": {
            "stored_tensor_element_count": 8,
            "safetensors_payload_bytes": 16,
        },
    }


class GpuMicrofitArgumentTests(unittest.TestCase):
    def test_parser_freezes_safe_diagnostic_defaults(self) -> None:
        arguments = gpu_microfit._build_parser().parse_args(
            ["--artifact-dir", "/tmp/model"]
        )
        self.assertEqual(arguments.batch_size, 1)
        self.assertEqual(arguments.sequence_length, 512)
        self.assertEqual(arguments.warmup_steps, 1)
        self.assertEqual(arguments.measured_steps, 3)
        self.assertEqual(arguments.seed, 20260714)
        self.assertEqual(arguments.learning_rate, 1e-5)
        self.assertEqual(arguments.weight_decay, 0.1)
        self.assertEqual(arguments.gradient_clip, 1.0)
        self.assertFalse(arguments.no_gradient_checkpointing)

    def test_numeric_parsers_reject_nonfinite_and_out_of_range_values(self) -> None:
        for parser, value in (
            (gpu_microfit._positive_int, "0"),
            (gpu_microfit._nonnegative_int, "-1"),
            (gpu_microfit._finite_positive_float, "nan"),
            (gpu_microfit._finite_positive_float, "0"),
            (gpu_microfit._finite_nonnegative_float, "inf"),
            (gpu_microfit._finite_nonnegative_float, "-0.1"),
        ):
            with self.subTest(parser=parser.__name__, value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    parser(value)


class GpuMicrofitTrustBoundaryTests(unittest.TestCase):
    def arguments(self, artifact: Path, **updates: object) -> argparse.Namespace:
        values: dict[str, object] = {
            "artifact_dir": artifact,
            "output": None,
            "expected_inspection_report_sha256": None,
            "batch_size": 1,
            "sequence_length": 8,
            "warmup_steps": 0,
            "measured_steps": 1,
            "seed": 1,
            "learning_rate": 1e-5,
            "weight_decay": 0.1,
            "gradient_clip": 1.0,
            "no_gradient_checkpointing": False,
        }
        values.update(updates)
        return argparse.Namespace(**values)

    def test_resource_ceilings_fail_before_artifact_or_runtime_loading(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact"
            artifact.mkdir()
            with mock.patch.object(
                gpu_microfit,
                "inspect_model_artifact",
                side_effect=AssertionError("must fail before inspection"),
            ):
                with self.assertRaisesRegex(
                    gpu_microfit.MicrofitError, "sequence length"
                ):
                    gpu_microfit._run(
                        self.arguments(artifact, sequence_length=16_385)
                    )
                with self.assertRaisesRegex(
                    gpu_microfit.MicrofitError, "optimizer steps"
                ):
                    gpu_microfit._run(
                        self.arguments(
                            artifact, warmup_steps=50, measured_steps=51
                        )
                    )

    def test_output_inside_model_fails_before_inspection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact"
            artifact.mkdir()
            output = artifact / "result.json"
            with mock.patch.object(
                gpu_microfit,
                "inspect_model_artifact",
                side_effect=AssertionError("must fail before inspection"),
            ):
                with self.assertRaisesRegex(
                    gpu_microfit.MicrofitError, "outside the model artifact"
                ):
                    gpu_microfit._run(self.arguments(artifact, output=output))
            self.assertFalse(output.exists())

    def test_expected_static_report_hash_mismatch_fails_before_ml_imports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact"
            artifact.mkdir()
            static = {
                "report_sha256": "a" * 64,
                "architecture": {"classification": "dense_consistent"},
                "claim_qualification": {
                    "stored_tensor_element_count_below_one_billion": True
                },
            }
            with mock.patch.object(
                gpu_microfit, "inspect_model_artifact", return_value=static
            ):
                with self.assertRaisesRegex(
                    gpu_microfit.MicrofitError, "does not match"
                ):
                    gpu_microfit._run(
                        self.arguments(
                            artifact,
                            expected_inspection_report_sha256="b" * 64,
                        )
                    )

    def test_fake_stack_happy_path_binds_stable_artifact_and_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact"
            artifact.mkdir()
            report = static_report()
            torch, transformers, loader = fake_stack()
            with mock.patch.object(
                gpu_microfit, "inspect_model_artifact", return_value=report
            ) as inspect, mock.patch.object(
                gpu_microfit, "_artifact_state", return_value=("stable",)
            ) as artifact_state, mock.patch.object(
                gpu_microfit,
                "_load_ml_dependencies",
                return_value=(torch, transformers, loader),
            ):
                record = gpu_microfit._run(
                    self.arguments(
                        artifact,
                        warmup_steps=1,
                        measured_steps=2,
                        seed=17,
                    )
                )

        self.assertEqual(inspect.call_count, 3)
        self.assertEqual(artifact_state.call_count, 3)
        self.assertEqual(len(loader.calls), 1)
        _, loader_kwargs = loader.calls[0]
        self.assertEqual(loader_kwargs["torch_dtype"], torch.bfloat16)
        self.assertNotIn("dtype", loader_kwargs)
        self.assertTrue(loader_kwargs["local_files_only"])
        self.assertFalse(loader_kwargs["trust_remote_code"])
        self.assertTrue(loader_kwargs["use_safetensors"])
        self.assertEqual(record["record_version"], "1.1.0")
        self.assertEqual(record["data_scope"], "seeded_synthetic_token_ids_only")
        self.assertFalse(
            record["reproducibility_scope"][
                "cuda_training_trajectory_determinism_guaranteed"
            ]
        )
        self.assertIn("os_socket_isolation_not_provided", record["network_access"])
        self.assertEqual(record["artifact"]["initial"], record["artifact"]["final"])
        self.assertTrue(record["artifact"]["content_and_metadata_match_after_load"])
        self.assertTrue(
            record["artifact"]["content_and_metadata_match_after_training"]
        )
        self.assertEqual(record["runtime"]["physical_parameter_elements"], 8)
        self.assertEqual(record["runtime"]["trainable_parameter_elements"], 8)
        self.assertEqual(record["measurements"]["measured_tokens"], 16)
        self.assertEqual(len(record["measurements"]["warmup_losses"]), 1)
        self.assertEqual(len(record["measurements"]["measured_losses"]), 2)
        self.assertEqual(len(torch.optim.instances), 1)
        optimizer = torch.optim.instances[0]
        self.assertEqual(optimizer.kwargs["betas"], (0.9, 0.95))
        self.assertTrue(optimizer.kwargs["fused"])
        self.assertEqual(optimizer.steps, 3)
        unsigned = dict(record)
        claimed = unsigned.pop("record_sha256")
        self.assertEqual(
            claimed,
            gpu_microfit.sha256(
                gpu_microfit.canonical_json_bytes(unsigned)
            ).hexdigest(),
        )

    def test_artifact_metadata_mutation_after_model_load_fails_before_training(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact"
            artifact.mkdir()
            initial = static_report()
            torch, transformers, loader = fake_stack()
            with mock.patch.object(
                gpu_microfit,
                "inspect_model_artifact",
                side_effect=(initial, initial),
            ), mock.patch.object(
                gpu_microfit,
                "_artifact_state",
                side_effect=(("stable",), ("changed",)),
            ), mock.patch.object(
                gpu_microfit,
                "_load_ml_dependencies",
                return_value=(torch, transformers, loader),
            ):
                with self.assertRaisesRegex(
                    gpu_microfit.MicrofitError, "artifact changed.*model load"
                ):
                    gpu_microfit._run(self.arguments(artifact))
        self.assertEqual(torch.optim.instances, [])

    def test_artifact_content_mutation_after_training_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact"
            artifact.mkdir()
            initial = static_report()
            changed = static_report("d" * 64)
            torch, transformers, loader = fake_stack()
            with mock.patch.object(
                gpu_microfit,
                "inspect_model_artifact",
                side_effect=(initial, initial, changed),
            ), mock.patch.object(
                gpu_microfit, "_artifact_state", return_value=("stable",)
            ), mock.patch.object(
                gpu_microfit,
                "_load_ml_dependencies",
                return_value=(torch, transformers, loader),
            ):
                with self.assertRaisesRegex(
                    gpu_microfit.MicrofitError, "artifact changed.*training"
                ):
                    gpu_microfit._run(self.arguments(artifact))
        self.assertEqual(len(torch.optim.instances), 1)
        self.assertEqual(torch.optim.instances[0].steps, 1)


if __name__ == "__main__":
    unittest.main()
