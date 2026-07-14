from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import unittest


from cbds.manifests import canonical_json_bytes, value_sha256
from cbds.model_artifacts import verify_inspection_report_sha256
from cbds.model_runtime import verify_runtime_report_sha256


ROOT = Path(__file__).resolve().parents[1]
REPORT_ROOT = ROOT / "reports" / "engineering-pilot"


class EngineeringPilotRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(
            (REPORT_ROOT / "manifest.json").read_text(encoding="utf-8")
        )

    def test_manifest_is_self_addressed_and_explicitly_nonclaiming(self) -> None:
        unsigned = dict(self.manifest)
        declared = unsigned.pop("manifest_sha256")
        self.assertEqual(declared, value_sha256(unsigned))
        self.assertEqual(self.manifest["claim_scope"], "none")
        self.assertFalse(self.manifest["selection_authorized"])
        self.assertFalse(self.manifest["sealed_data_accessed"])
        self.assertEqual(self.manifest["schema_version"], "1.1.0")
        self.assertFalse(self.manifest["host"]["os_socket_isolation_provided"])
        self.assertFalse(
            self.manifest["microfit_configuration"][
                "deterministic_algorithms_enforced"
            ]
        )

    def test_bound_code_sources_are_well_formed_historical_provenance(self) -> None:
        """A completed report binds the bytes used then, not today's checkout.

        Requiring every bound source to remain byte-identical would either make
        normal maintenance impossible or encourage rewriting a historical
        record after code changes.  The per-report tests below verify the
        runtime and microfit implementation hashes against these immutable
        bindings; this test keeps their shape and repository-relative identity
        strict without relabelling current source as previously executed code.
        """

        for relative, expected in self.manifest["code_sources"].items():
            with self.subTest(path=relative):
                self.assertFalse(Path(relative).is_absolute())
                self.assertNotIn("..", Path(relative).parts)
                self.assertTrue((ROOT / relative).is_file())
                self.assertRegex(expected, r"\A[0-9a-f]{64}\Z")

    def test_every_report_file_and_internal_record_hash_verifies(self) -> None:
        for model in self.manifest["models"]:
            with self.subTest(model=model["model_id"]):
                static_binding = model["static_report"]
                runtime_binding = model["runtime_report"]
                microfit_binding = model["microfit_report"]
                static_path = REPORT_ROOT / static_binding["path"]
                runtime_path = REPORT_ROOT / runtime_binding["path"]
                microfit_path = REPORT_ROOT / microfit_binding["path"]
                for path, binding in (
                    (static_path, static_binding),
                    (runtime_path, runtime_binding),
                    (microfit_path, microfit_binding),
                ):
                    self.assertEqual(
                        sha256(path.read_bytes()).hexdigest(),
                        binding["file_sha256"],
                    )

                static = json.loads(static_path.read_text(encoding="utf-8"))
                runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
                microfit = json.loads(microfit_path.read_text(encoding="utf-8"))
                self.assertTrue(verify_inspection_report_sha256(static))
                self.assertTrue(verify_runtime_report_sha256(runtime))
                unsigned_microfit = dict(microfit)
                microfit_hash = unsigned_microfit.pop("record_sha256")
                self.assertEqual(
                    microfit_hash,
                    sha256(canonical_json_bytes(unsigned_microfit)).hexdigest(),
                )
                self.assertEqual(static["report_sha256"], static_binding["report_sha256"])
                self.assertEqual(runtime["report_sha256"], runtime_binding["report_sha256"])
                self.assertEqual(microfit_hash, microfit_binding["record_sha256"])

                self.assertEqual(
                    runtime["static_inspection"]["report_sha256"],
                    static["report_sha256"],
                )
                self.assertEqual(
                    runtime["implementation"]["source_sha256"],
                    self.manifest["code_sources"]["src/cbds/model_runtime.py"],
                )
                self.assertFalse(
                    runtime["load_policy"]["os_socket_isolation_provided"]
                )
                self.assertEqual(
                    runtime["parameters"]["physical_elements"],
                    model["physical_parameters"],
                )
                self.assertEqual(
                    microfit["runtime"]["physical_parameter_elements"],
                    model["physical_parameters"],
                )
                self.assertEqual(
                    microfit["implementation"]["script_sha256"],
                    self.manifest["code_sources"]["scripts/gpu_microfit.py"],
                )
                self.assertTrue(
                    microfit["artifact"]["content_and_metadata_match_after_load"]
                )
                self.assertTrue(
                    microfit["artifact"][
                        "content_and_metadata_match_after_training"
                    ]
                )
                for phase in ("initial", "after_load", "final"):
                    self.assertEqual(
                        microfit["artifact"][phase]["inspection_report_sha256"],
                        static["report_sha256"],
                    )
                self.assertFalse(
                    microfit["reproducibility_scope"][
                        "cuda_training_trajectory_determinism_guaranteed"
                    ]
                )
                self.assertEqual(
                    microfit["runtime"]["device_total_memory_bytes"],
                    self.manifest["host"][
                        "torch_cuda_get_device_properties_total_memory_bytes"
                    ],
                )
                self.assertEqual(microfit["claim_scope"], "none")
                self.assertEqual(
                    microfit["measurements"]["optimizer_visible_tokens_per_second"],
                    microfit_binding["optimizer_visible_tokens_per_second"],
                )
                self.assertEqual(
                    microfit["measurements"]["milliseconds_per_optimizer_step"],
                    microfit_binding["milliseconds_per_optimizer_step"],
                )

    def test_portable_records_do_not_embed_local_cache_or_tmp_paths(self) -> None:
        for path in REPORT_ROOT.glob("*.json"):
            payload = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertNotIn("/home/", payload)
                self.assertNotIn("/tmp/", payload)


if __name__ == "__main__":
    unittest.main()
