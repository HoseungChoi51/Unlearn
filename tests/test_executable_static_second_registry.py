from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_fixture_catalog import (  # noqa: E402
    build_fixture_bundle_for_task_profile,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_static_registry import (  # noqa: E402
    build_public_method_development_registry,
)
from cbds.executable_static_second_registry import (  # noqa: E402
    LINE_TRANSFORMS,
    LINE_TRANSFORM_SUFFIXES,
    build_line_transform_mirror_tasks,
)
from cbds.executable_static_types import (  # noqa: E402
    LineTransformMirrorParameters,
    parameter_record,
)


FROZEN_FIRST_REGISTRY_SHA256 = (
    "ada6043b345e48f69ad602581030aab1bafcb3ff9dc453f9d02342faaf6a7f9a"
)
FROZEN_FIRST_SUITE_SHA256 = (
    "eb64bb4cdb60ab8e0e228f688cf54810fae2ef56768e8b34ac039bdc1aec42ae"
)


class LineTransformSecondRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = build_line_transform_mirror_tasks()

    def test_additive_grid_is_exact_unique_and_canonically_ordered(self) -> None:
        self.assertEqual(len(self.tasks), 20)
        observed = tuple(
            (task.parameters.suffix, task.parameters.transform)
            for task in self.tasks
            if type(task.parameters) is LineTransformMirrorParameters
        )
        expected = tuple(
            (suffix, transform)
            for suffix in LINE_TRANSFORM_SUFFIXES
            for transform in LINE_TRANSFORMS
        )
        self.assertEqual(observed, expected)
        self.assertEqual(len({task.task_id for task in self.tasks}), 20)
        self.assertEqual(len({task.task_contract_sha256 for task in self.tasks}), 20)
        self.assertEqual(len({task.graph_sha256 for task in self.tasks}), 20)

    def test_contracts_are_public_unsealed_and_closed(self) -> None:
        for task in self.tasks:
            with self.subTest(task_id=task.task_id):
                task.__post_init__()
                self.assertEqual(task.family_id, "line-transform-mirror")
                self.assertEqual(task.filesystem_identity, "mixed-byte-text-tree-v1")
                self.assertEqual(task.output_identity, "exact-transformed-mirror-v1")
                self.assertEqual(
                    task.allowed_tools,
                    ("cp", "find", "mkdir", "sed", "tr"),
                )
                self.assertTrue(task.public)
                self.assertFalse(task.sealed)
                self.assertFalse(task.claim_authorized)
                self.assertEqual(len(task.fixtures), 5)
                self.assertIn(task.parameters.suffix, task.prompt)
                graph_parameters = {
                    parameter
                    for node in task.graph.nodes
                    for parameter in node.parameters
                }
                self.assertIn(
                    f"transform:{task.parameters.transform}",
                    graph_parameters,
                )

    def test_every_descriptor_rebuilds_from_its_task_and_profile(self) -> None:
        for task in self.tasks:
            for index, profile in enumerate(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES):
                with self.subTest(task_id=task.task_id, profile=profile.profile_id):
                    bundle = build_fixture_bundle_for_task_profile(task, profile)
                    self.assertEqual(bundle.descriptor, task.fixtures[index])
                    self.assertEqual(
                        bundle.oracle.semantic_verifier_identity,
                        "verify-line-transform-mirror-v1",
                    )

    def test_parameter_and_task_frozen_bypasses_are_revalidated(self) -> None:
        parameters = self.tasks[0].parameters
        self.assertIs(type(parameters), LineTransformMirrorParameters)
        original = parameters.transform
        try:
            object.__setattr__(parameters, "transform", "not-a-transform")
            with self.assertRaises(ValueError):
                parameter_record(parameters)
            with self.assertRaises(ValueError):
                self.tasks[0].__post_init__()
        finally:
            object.__setattr__(parameters, "transform", original)
        self.tasks[0].__post_init__()

    def test_frozen_first_registry_is_unchanged(self) -> None:
        registry = build_public_method_development_registry()
        self.assertEqual(registry.registry_sha256, FROZEN_FIRST_REGISTRY_SHA256)
        self.assertEqual(registry.suite_sha256, FROZEN_FIRST_SUITE_SHA256)
        self.assertEqual(len(registry.tasks), 100)
        self.assertNotIn(
            "line-transform-mirror",
            {task.family_id for task in registry.tasks},
        )


if __name__ == "__main__":
    unittest.main()
