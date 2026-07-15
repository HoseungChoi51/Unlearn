from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_fixture_catalog import (  # noqa: E402
    build_first_tranche_fixture_catalog,
)
from cbds.executable_fixture_verifier import (  # noqa: E402
    verify_executable_fixture,
)
from cbds.executable_static_registry import (  # noqa: E402
    build_public_method_development_registry,
)
from cbds.executable_workspace import materialize_fixture  # noqa: E402


REGISTRY = build_public_method_development_registry()
CATALOG = build_first_tranche_fixture_catalog(REGISTRY)


def _write_trusted_oracle(workspace: Path, bundle: object) -> None:
    for output in bundle.oracle.outputs:  # type: ignore[attr-defined]
        target = workspace / output.path
        target.parent.mkdir(parents=True, exist_ok=True)
        relative_parent = target.parent.relative_to(workspace)
        current = workspace
        for component in relative_parent.parts:
            current /= component
            current.chmod(0o755)
        target.write_bytes(output.content)
        target.chmod(output.mode)


class FullCatalogMaterializationTests(unittest.TestCase):
    def test_all_500_bundles_materialize_and_verify_without_execution(self) -> None:
        family_passes: dict[str, int] = {}
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            subprocess,
            "run",
            side_effect=AssertionError("subprocess.run executed"),
        ), mock.patch.object(
            subprocess,
            "Popen",
            side_effect=AssertionError("subprocess.Popen executed"),
        ), mock.patch.object(
            os,
            "system",
            side_effect=AssertionError("os.system executed"),
        ):
            root = Path(temporary)
            for index, bundle in enumerate(CATALOG.bundles):
                task = REGISTRY.tasks[index // 5]
                workspace = root / f"fixture-{index:03d}"
                with self.subTest(index=index, family=task.family_id):
                    with materialize_fixture(
                        bundle.definition, workspace
                    ) as handle:
                        self.assertEqual(handle.scan_outputs().entries, ())
                        _write_trusted_oracle(workspace, bundle)
                        evidence = verify_executable_fixture(bundle, handle)
                        self.assertTrue(evidence.passed, evidence.failure_code)
                        self.assertEqual(
                            len(evidence.outputs), len(bundle.oracle.outputs)
                        )
                        family_passes[task.family_id] = (
                            family_passes.get(task.family_id, 0) + 1
                        )

        self.assertEqual(
            family_passes,
            {
                "active-jsonl-labels": 100,
                "manifest-copy": 100,
                "csv-group-totals": 100,
                "checksum-manifest": 100,
                "path-suffix-inventory": 100,
            },
        )

    def test_one_byte_or_size_mutation_is_rejected_for_every_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, bundle in enumerate(CATALOG.bundles):
                workspace = root / f"mutated-{index:03d}"
                with self.subTest(index=index):
                    with materialize_fixture(
                        bundle.definition, workspace
                    ) as handle:
                        _write_trusted_oracle(workspace, bundle)
                        first = bundle.oracle.outputs[0]
                        target = workspace / first.path
                        if first.content:
                            changed = bytes([first.content[0] ^ 1]) + first.content[1:]
                        else:
                            changed = b"x"
                        target.write_bytes(changed)
                        target.chmod(first.mode)
                        evidence = verify_executable_fixture(bundle, handle)
                        self.assertFalse(evidence.passed)
                        self.assertIn(
                            evidence.failure_code,
                            {
                                "output-policy-failure",
                                "malformed-semantic-output",
                                "semantic-mismatch",
                            },
                        )


if __name__ == "__main__":
    unittest.main()
