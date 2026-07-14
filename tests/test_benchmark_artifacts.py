from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.benchmark import BenchmarkConfig, canonical_json, prepare_benchmark  # noqa: E402
from cbds.benchmark_artifacts import (  # noqa: E402
    BenchmarkArtifactValidationError,
    compute_manifest_sidecar,
    load_benchmark_manifest,
    validate_benchmark_artifacts,
)
import cbds.benchmark_artifacts as benchmark_artifacts  # noqa: E402


def _manifest(root: Path) -> dict[str, object]:
    value = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _reseal_manifest(root: Path, manifest: dict[str, object]) -> None:
    core = {
        key: value
        for key, value in manifest.items()
        if key not in {"dataset_hash_scope", "dataset_sha256"}
    }
    manifest["dataset_sha256"] = sha256(
        canonical_json(core).encode("utf-8")
    ).hexdigest()
    payload = (canonical_json(manifest) + "\n").encode("utf-8")
    (root / "manifest.json").write_bytes(payload)
    (root / "manifest.sha256").write_bytes(compute_manifest_sidecar(payload))


def _file_declaration(
    manifest: dict[str, object], relative_path: str
) -> dict[str, object]:
    files = manifest["files"]
    assert isinstance(files, list)
    result = next(
        item
        for item in files
        if isinstance(item, dict) and item.get("path") == relative_path
    )
    assert isinstance(result, dict)
    return result


def _refresh_file_declaration(
    root: Path, manifest: dict[str, object], relative_path: str
) -> None:
    payload = (root / relative_path).read_bytes()
    declaration = _file_declaration(manifest, relative_path)
    declaration["bytes"] = len(payload)
    declaration["sha256"] = sha256(payload).hexdigest()


class ArtifactTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "dataset"
        self.prepared = prepare_benchmark(BenchmarkConfig(), self.root)

    def assert_artifact_error(self, fragment: str, **kwargs: object) -> None:
        with self.assertRaises(BenchmarkArtifactValidationError) as caught:
            validate_benchmark_artifacts(self.root, **kwargs)  # type: ignore[arg-type]
        self.assertIn(fragment, str(caught.exception))


class HappyPathTests(ArtifactTestCase):
    def test_valid_bundle_returns_content_free_machine_summary(self) -> None:
        manifest_payload = (self.root / "manifest.json").read_bytes()
        summary = validate_benchmark_artifacts(
            self.root,
            expected_dataset_sha256=str(self.prepared["dataset_sha256"]),
            expected_manifest_sha256=sha256(manifest_payload).hexdigest(),
        )
        self.assertTrue(summary["valid"])
        self.assertEqual(summary["file_count"], 12)
        self.assertEqual(summary["total_records"], self.prepared["total_records"])
        self.assertEqual(summary["dataset_sha256"], self.prepared["dataset_sha256"])
        encoded = canonical_json(summary)
        self.assertNotIn("prompt", encoded)
        self.assertNotIn("fixture_id", encoded)
        self.assertNotIn("spec_id", encoded)

    def test_manifest_path_and_directory_loading_are_equivalent(self) -> None:
        from_directory = load_benchmark_manifest(self.root)
        from_file = load_benchmark_manifest(self.root / "manifest.json")
        self.assertEqual(from_directory, from_file)

    def test_sidecar_computation_has_exact_portable_format(self) -> None:
        payload = (self.root / "manifest.json").read_bytes()
        expected = (
            f"{sha256(payload).hexdigest()}  manifest.json\n".encode("ascii")
        )
        self.assertEqual(compute_manifest_sidecar(payload), expected)

    def test_explicit_extra_file_tolerance_does_not_weaken_content_checks(self) -> None:
        (self.root / "monitoring-note.txt").write_text("local\n", encoding="utf-8")
        self.assert_artifact_error("undeclared files")
        summary = validate_benchmark_artifacts(
            self.root, reject_extra_files=False
        )
        self.assertTrue(summary["valid"])


class ManifestTamperTests(ArtifactTestCase):
    def test_changed_or_malformed_external_pins_fail_closed(self) -> None:
        self.assert_artifact_error(
            "does not match expected_dataset_sha256",
            expected_dataset_sha256="0" * 64,
        )
        self.assert_artifact_error(
            "does not match expected_manifest_sha256",
            expected_manifest_sha256="0" * 64,
        )
        with self.assertRaisesRegex(ValueError, "lowercase SHA-256"):
            validate_benchmark_artifacts(
                self.root, expected_dataset_sha256="not-a-digest"
            )

    def test_sidecar_tamper_is_detected_from_exact_manifest_bytes(self) -> None:
        (self.root / "manifest.sha256").write_text(
            f"{'0' * 64}  manifest.json\n", encoding="ascii"
        )
        self.assert_artifact_error("manifest.sha256 does not match")

    def test_pretty_printed_manifest_is_rejected_even_with_fresh_sidecar(self) -> None:
        manifest = _manifest(self.root)
        payload = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        (self.root / "manifest.json").write_bytes(payload)
        (self.root / "manifest.sha256").write_bytes(
            compute_manifest_sidecar(payload)
        )
        self.assert_artifact_error("not exact canonical JSON")

    def test_duplicate_manifest_key_is_rejected_before_artifact_access(self) -> None:
        (self.root / "manifest.json").write_text(
            '{"schema_version":"1.0.0","schema_version":"1.0.0"}\n',
            encoding="utf-8",
        )
        self.assert_artifact_error("duplicate object key")

    def test_pathological_json_integer_is_wrapped_as_artifact_failure(self) -> None:
        (self.root / "manifest.json").write_text(
            '{"integer":' + ("9" * 10_000) + "}\n",
            encoding="utf-8",
        )
        self.assert_artifact_error("invalid JSON value")

    def test_traversal_declaration_is_rejected_even_when_resealed(self) -> None:
        manifest = _manifest(self.root)
        declaration = _file_declaration(manifest, "static/train.jsonl")
        declaration["path"] = "../outside.jsonl"
        _reseal_manifest(self.root, manifest)
        self.assert_artifact_error("canonical safe relative path")

    def test_wrong_path_suite_split_binding_is_rejected(self) -> None:
        manifest = _manifest(self.root)
        declaration = _file_declaration(manifest, "static/train.jsonl")
        declaration["path"] = "static/shadow_validation.jsonl"
        _reseal_manifest(self.root, manifest)
        self.assert_artifact_error("duplicate declared file paths")
        self.assert_artifact_error("must equal 'static/train.jsonl'")

    def test_manifest_count_tamper_is_rejected_against_config(self) -> None:
        manifest = _manifest(self.root)
        declaration = _file_declaration(manifest, "static/train.jsonl")
        declaration["records"] = int(declaration["records"]) - 1
        manifest["total_records"] = int(manifest["total_records"]) - 1
        _reseal_manifest(self.root, manifest)
        self.assert_artifact_error("must equal config count")

    def test_manifest_config_must_not_inherit_hidden_defaults(self) -> None:
        manifest = _manifest(self.root)
        config = manifest["config"]
        assert isinstance(config, dict)
        del config["family_size"]
        _reseal_manifest(self.root, manifest)
        self.assert_artifact_error("config is missing keys ['family_size']")

    def test_every_split_count_must_be_explicit(self) -> None:
        manifest = _manifest(self.root)
        config = manifest["config"]
        assert isinstance(config, dict)
        static = config["static"]
        assert isinstance(static, dict)
        del static["shadow_validation"]
        _reseal_manifest(self.root, manifest)
        self.assert_artifact_error(
            "config.static is missing keys ['shadow_validation']"
        )

    def test_huge_self_consistent_declarations_stop_before_regeneration(self) -> None:
        manifest = _manifest(self.root)
        config = manifest["config"]
        assert isinstance(config, dict)
        static = config["static"]
        assert isinstance(static, dict)
        old_count = int(static["train"])
        static["train"] = 1_000_000_000
        declaration = _file_declaration(manifest, "static/train.jsonl")
        declaration["records"] = 1_000_000_000
        manifest["total_records"] = (
            int(manifest["total_records"]) - old_count + 1_000_000_000
        )
        _reseal_manifest(self.root, manifest)
        self.assert_artifact_error("total_records exceeds validation ceiling")

    def test_huge_fixture_count_stops_before_regeneration(self) -> None:
        manifest = _manifest(self.root)
        config = manifest["config"]
        assert isinstance(config, dict)
        config["fixture_count"] = 1_000_000_000
        _reseal_manifest(self.root, manifest)
        self.assert_artifact_error("total generated fixtures exceed validation ceiling")

    def test_missing_suite_split_declaration_is_rejected(self) -> None:
        manifest = _manifest(self.root)
        files = manifest["files"]
        assert isinstance(files, list)
        manifest["files"] = [
            item
            for item in files
            if not isinstance(item, dict)
            or item.get("path") != "interactive/sealed_ood.jsonl"
        ]
        manifest["total_records"] = int(manifest["total_records"]) - 2
        _reseal_manifest(self.root, manifest)
        self.assert_artifact_error("missing suite/split declarations")


class FilesystemBoundaryTests(ArtifactTestCase):
    def test_inventory_entry_limit_fails_closed(self) -> None:
        self.assert_artifact_error(
            "artifact inventory exceeds 1 entries", max_inventory_entries=1
        )

    def test_missing_declared_file_is_rejected(self) -> None:
        (self.root / "static" / "train.jsonl").unlink()
        self.assert_artifact_error("artifact directory is missing files")

    def test_undeclared_directory_is_rejected(self) -> None:
        (self.root / "notes").mkdir()
        self.assert_artifact_error("undeclared directories")

    def test_declared_symlink_is_rejected_without_following_it(self) -> None:
        target = self.root / "outside-secret.jsonl"
        target.write_text("do not read\n", encoding="utf-8")
        declared = self.root / "static" / "train.jsonl"
        declared.unlink()
        try:
            declared.symlink_to(target)
        except (NotImplementedError, OSError) as error:  # pragma: no cover
            self.skipTest(f"symlinks unavailable: {error}")
        self.assert_artifact_error("must not be a symlink")

    def test_symlinked_manifest_is_rejected(self) -> None:
        real = self.root / "real-manifest.json"
        (self.root / "manifest.json").replace(real)
        try:
            (self.root / "manifest.json").symlink_to(real)
        except (NotImplementedError, OSError) as error:  # pragma: no cover
            self.skipTest(f"symlinks unavailable: {error}")
        self.assert_artifact_error("manifest.json must not be a symlink")

    def test_manifest_replacement_after_root_open_is_not_followed(self) -> None:
        victim = self.root.parent / "outside-secret.json"
        secret = b'SEALED_SECRET_DO_NOT_READ'
        victim.write_bytes(secret)
        manifest_path = self.root / "manifest.json"
        original_open = os.open
        swapped = False

        def racing_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
            nonlocal swapped
            if path == "manifest.json" and kwargs.get("dir_fd") is not None and not swapped:
                swapped = True
                manifest_path.unlink()
                manifest_path.symlink_to(victim)
            return original_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

        with mock.patch.object(benchmark_artifacts.os, "open", side_effect=racing_open):
            with self.assertRaises(BenchmarkArtifactValidationError) as caught:
                validate_benchmark_artifacts(self.root)
        self.assertTrue(swapped)
        self.assertIn("must not be a symlink", str(caught.exception))
        self.assertNotIn(secret.decode("ascii"), str(caught.exception))

    def test_jsonl_replacement_during_read_is_detected_without_following(self) -> None:
        declared = self.root / "static" / "train.jsonl"
        victim = self.root.parent / "outside-secret.jsonl"
        secret = b'SEALED_JSONL_SECRET_DO_NOT_READ\n'
        victim.write_bytes(secret)
        original_read = os.read
        swapped = False

        def racing_read(descriptor: int, size: int) -> bytes:
            nonlocal swapped
            if not swapped:
                try:
                    target = Path(f"/proc/self/fd/{descriptor}").resolve(strict=True)
                except OSError:
                    target = None
                if target == declared:
                    swapped = True
                    declared.unlink()
                    declared.symlink_to(victim)
            return original_read(descriptor, size)

        with mock.patch.object(benchmark_artifacts.os, "read", side_effect=racing_read):
            with self.assertRaises(BenchmarkArtifactValidationError) as caught:
                validate_benchmark_artifacts(self.root)
        self.assertTrue(swapped)
        self.assertIn("changed during validation", str(caught.exception))
        self.assertNotIn(secret.decode("ascii").strip(), str(caught.exception))


class JsonlTamperTests(ArtifactTestCase):
    def test_unsealed_byte_tamper_breaks_size_and_hash(self) -> None:
        path = self.root / "static" / "train.jsonl"
        with path.open("ab") as handle:
            handle.write(b"\n")
        with self.assertRaises(BenchmarkArtifactValidationError) as caught:
            validate_benchmark_artifacts(self.root)
        message = str(caught.exception)
        self.assertIn("byte count mismatch", message)
        self.assertIn("SHA-256 mismatch", message)

    def test_actual_byte_ceiling_is_checked_before_hashing_or_parsing(self) -> None:
        declared_total = sum(
            int(item["bytes"])
            for item in self.prepared["files"]  # type: ignore[union-attr]
        )
        path = self.root / "static" / "train.jsonl"
        with path.open("ab") as handle:
            handle.write(b"ten-bytes!\n")
        self.assert_artifact_error(
            "actual JSONL bytes exceed validation ceiling",
            max_total_jsonl_bytes=declared_total + 5,
        )

    def test_rehashed_semantic_tamper_fails_generator_equivalence(self) -> None:
        relative = "static/train.jsonl"
        path = self.root / relative
        records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        records[0]["prompt"] += " Mutated after sealing."
        path.write_text(
            "".join(canonical_json(record) + "\n" for record in records),
            encoding="utf-8",
            newline="\n",
        )
        manifest = _manifest(self.root)
        _refresh_file_declaration(self.root, manifest, relative)
        _reseal_manifest(self.root, manifest)
        self.assert_artifact_error("differ from deterministic generator output")

    def test_unknown_record_field_is_not_silently_discarded(self) -> None:
        relative = "interactive/train.jsonl"
        path = self.root / relative
        records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        records[0]["unmanifested_note"] = "not part of SemanticSpec"
        path.write_text(
            "".join(canonical_json(record) + "\n" for record in records),
            encoding="utf-8",
            newline="\n",
        )
        manifest = _manifest(self.root)
        _refresh_file_declaration(self.root, manifest, relative)
        _reseal_manifest(self.root, manifest)
        self.assert_artifact_error("record is not exact canonical JSONL")

    def test_record_suite_split_mismatch_is_reported(self) -> None:
        relative = "static/train.jsonl"
        path = self.root / relative
        records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        records[0]["split"] = "sealed_id"
        path.write_text(
            "".join(canonical_json(record) + "\n" for record in records),
            encoding="utf-8",
            newline="\n",
        )
        manifest = _manifest(self.root)
        _refresh_file_declaration(self.root, manifest, relative)
        _reseal_manifest(self.root, manifest)
        self.assert_artifact_error("incorrect suite/split metadata")

    def test_malformed_typed_record_is_rejected_after_resealing(self) -> None:
        relative = "interactive/sealed_id.jsonl"
        path = self.root / relative
        records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        records[0]["fixtures"] = "not-a-list"
        path.write_text(
            "".join(canonical_json(record) + "\n" for record in records),
            encoding="utf-8",
            newline="\n",
        )
        manifest = _manifest(self.root)
        _refresh_file_declaration(self.root, manifest, relative)
        _reseal_manifest(self.root, manifest)
        self.assert_artifact_error("typed JSONL load failed")

    def test_typed_load_error_does_not_echo_sealed_record_content(self) -> None:
        relative = "static/train.jsonl"
        path = self.root / relative
        records = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
        ]
        secret = "SEALED_PROMPT_FRAGMENT_DO_NOT_LOG"
        records[0]["suite"] = secret
        path.write_text(
            "".join(canonical_json(record) + "\n" for record in records),
            encoding="utf-8",
            newline="\n",
        )
        manifest = _manifest(self.root)
        _refresh_file_declaration(self.root, manifest, relative)
        _reseal_manifest(self.root, manifest)
        with self.assertRaises(BenchmarkArtifactValidationError) as caught:
            validate_benchmark_artifacts(self.root)
        message = str(caught.exception)
        self.assertIn("typed JSONL load failed", message)
        self.assertNotIn(secret, message)

    def test_sealed_record_identifiers_do_not_cross_error_boundary(self) -> None:
        relative = "static/sealed_id.jsonl"
        path = self.root / relative
        records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        sealed_spec_id = records[0]["spec_id"]
        records[0]["graph_hash"] = "0" * 64
        path.write_text(
            "".join(canonical_json(record) + "\n" for record in records),
            encoding="utf-8",
            newline="\n",
        )
        manifest = _manifest(self.root)
        _refresh_file_declaration(self.root, manifest, relative)
        _reseal_manifest(self.root, manifest)
        with self.assertRaises(BenchmarkArtifactValidationError) as caught:
            validate_benchmark_artifacts(self.root)
        self.assertIn("typed benchmark invariant validation failed", str(caught.exception))
        self.assertNotIn(str(sealed_spec_id), str(caught.exception))


if __name__ == "__main__":
    unittest.main()
