from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_static_registry import (  # noqa: E402
    ACTIVE_LABEL_KEYS,
    ACTIVE_PREDICATES,
    CHECKSUM_LAYOUTS,
    CHECKSUM_POLICIES,
    COLLISION_POLICIES,
    COPY_SELECTORS,
    CSV_LAYOUTS,
    CSV_PREDICATES,
    PATH_DEPTHS,
    PATH_SUFFIXES,
    build_public_method_development_registry,
    compute_registry_sha256,
    compute_suite_sha256,
)
from cbds.benchmark import NormalizedSemanticGraph, OperatorNode  # noqa: E402
from cbds.executable_fixture_catalog import (  # noqa: E402
    build_fixture_bundle_for_task_profile,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_static_types import (  # noqa: E402
    ActiveJsonlLabelsParameters,
    ChecksumManifestParameters,
    CsvGroupTotalsParameters,
    ExecutableStaticRegistry,
    ManifestCopyParameters,
    OpaqueFixtureDescriptor,
    PathSuffixInventoryParameters,
    compute_task_contract_sha256,
    parameter_record,
    task_id_from_contract,
)


class ParameterContractTests(unittest.TestCase):
    def test_axes_are_exact_four_by_five_sets(self) -> None:
        for axis in (
            ACTIVE_LABEL_KEYS,
            COPY_SELECTORS,
            CSV_LAYOUTS,
            CHECKSUM_LAYOUTS,
            PATH_SUFFIXES,
        ):
            self.assertEqual(len(axis), 4)
            self.assertEqual(len(set(axis)), 4)
        for axis in (
            ACTIVE_PREDICATES,
            COLLISION_POLICIES,
            CSV_PREDICATES,
            CHECKSUM_POLICIES,
            PATH_DEPTHS,
        ):
            self.assertEqual(len(axis), 5)
            self.assertEqual(len(set(axis)), 5)

    def test_parameter_types_are_closed_and_frozen(self) -> None:
        valid = ActiveJsonlLabelsParameters("label", "active-true")
        with self.assertRaises(FrozenInstanceError):
            valid.label_key = "name"  # type: ignore[misc]

        invalid_constructors = (
            lambda: ActiveJsonlLabelsParameters("other", "active-true"),
            lambda: ManifestCopyParameters("all-readable", "merge"),
            lambda: CsvGroupTotalsParameters("unknown", "all-valid"),
            lambda: ChecksumManifestParameters("json-object-lines", "weak"),
            lambda: PathSuffixInventoryParameters(".py", 1),
            lambda: PathSuffixInventoryParameters(".txt", 0),
            lambda: PathSuffixInventoryParameters(".txt", True),
        )
        for constructor in invalid_constructors:
            with self.subTest(constructor=constructor):
                with self.assertRaises(ValueError):
                    constructor()  # type: ignore[operator]

    def test_parameter_records_are_typed_not_free_form_mappings(self) -> None:
        values = (
            ActiveJsonlLabelsParameters("title", "deleted-false"),
            ManifestCopyParameters("selected-true", "last-record"),
            CsvGroupTotalsParameters("amount-enabled-category", "positive-amount"),
            ChecksumManifestParameters("nul-triplets", "mode-only"),
            PathSuffixInventoryParameters(".csv", "unbounded"),
        )
        for value in values:
            record = parameter_record(value)
            self.assertIn("parameter_type", record)
            self.assertEqual(len(record), 3)
        with self.assertRaises(TypeError):
            parameter_record({"parameter_type": "active-jsonl-labels"})  # type: ignore[arg-type]


class RegistryConstructionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = build_public_method_development_registry()

    def test_exact_counts_and_family_balance(self) -> None:
        selected = self.registry
        self.assertEqual(len(selected.tasks), 100)
        self.assertEqual(sum(len(task.fixtures) for task in selected.tasks), 500)
        family_counts = {
            family: sum(task.family_id == family for task in selected.tasks)
            for family in {task.family_id for task in selected.tasks}
        }
        self.assertEqual(
            family_counts,
            {
                "active-jsonl-labels": 20,
                "manifest-copy": 20,
                "csv-group-totals": 20,
                "checksum-manifest": 20,
                "path-suffix-inventory": 20,
            },
        )
        self.assertTrue(all(len(task.fixtures) == 5 for task in selected.tasks))

    def test_all_task_graph_and_fixture_identities_are_unique(self) -> None:
        tasks = self.registry.tasks
        self.assertEqual(len({task.task_id for task in tasks}), 100)
        self.assertEqual(len({task.task_contract_sha256 for task in tasks}), 100)
        self.assertEqual(len({task.graph_sha256 for task in tasks}), 100)
        fixture_ids = [item.fixture_id for task in tasks for item in task.fixtures]
        fixture_hashes = [item.fixture_sha256 for task in tasks for item in task.fixtures]
        self.assertEqual(len(set(fixture_ids)), 500)
        self.assertEqual(len(set(fixture_hashes)), 500)

    def test_task_ids_reconstruct_from_semantics_without_ordinal_or_salt(self) -> None:
        for task in self.registry.tasks:
            recomputed = compute_task_contract_sha256(
                family_id=task.family_id,
                family_version=task.family_version,
                parameters=task.parameters,
                prompt=task.prompt,
                graph=task.graph,
                filesystem_identity=task.filesystem_identity,
                output_identity=task.output_identity,
                allowed_tools=task.allowed_tools,
            )
            self.assertEqual(recomputed, task.task_contract_sha256)
            self.assertEqual(task.task_id, task_id_from_contract(recomputed))
            public = task.to_public_record()
            self.assertNotIn("ordinal", public)
            self.assertNotIn("variant_index", public)
            self.assertNotIn("seed", public)

    def test_every_axis_value_enters_the_semantic_graph(self) -> None:
        for task in self.registry.tasks:
            encoded_graph = json.dumps(task.graph.to_record(), sort_keys=True)
            parameters = parameter_record(task.parameters)
            for name, value in parameters.items():
                if name == "parameter_type":
                    continue
                with self.subTest(task=task.task_id, parameter=name):
                    self.assertIn(str(value), encoded_graph)

    def test_graphs_are_nonempty_forward_dags_bound_to_declared_hashes(self) -> None:
        for task in self.registry.tasks:
            self.assertGreaterEqual(len(task.graph.nodes), 4)
            self.assertEqual(task.graph.hash, task.graph_sha256)
            for source, target in task.graph.dependencies:
                self.assertLess(source, target)

    def test_build_is_deterministic_with_stable_golden_identities(self) -> None:
        repeated = build_public_method_development_registry()
        self.assertEqual(
            self.registry.to_public_projection(), repeated.to_public_projection()
        )
        self.assertEqual(
            self.registry.registry_sha256,
            "ada6043b345e48f69ad602581030aab1bafcb3ff9dc453f9d02342faaf6a7f9a",
        )
        self.assertEqual(
            self.registry.suite_sha256,
            "eb64bb4cdb60ab8e0e228f688cf54810fae2ef56768e8b34ac039bdc1aec42ae",
        )
        self.assertEqual(
            self.registry.registry_sha256,
            compute_registry_sha256(self.registry.tasks),
        )
        self.assertEqual(
            self.registry.suite_sha256,
            compute_suite_sha256(
                self.registry.tasks, self.registry.registry_sha256
            ),
        )

    def test_registry_rejects_duplicate_task_or_graph_and_bad_boundaries(self) -> None:
        tasks = self.registry.tasks
        with self.assertRaisesRegex(ValueError, "task IDs"):
            ExecutableStaticRegistry(
                tasks=(*tasks[:-1], tasks[0]),
                registry_sha256=self.registry.registry_sha256,
                suite_sha256=self.registry.suite_sha256,
            )
        graph_duplicate = replace(
            tasks[-1],
            graph=tasks[0].graph,
            task_contract_sha256=tasks[0].task_contract_sha256,
            task_id=tasks[0].task_id,
            fixtures=tasks[0].fixtures,
            family_id=tasks[0].family_id,
            parameters=tasks[0].parameters,
            prompt=tasks[0].prompt,
            filesystem_identity=tasks[0].filesystem_identity,
            output_identity=tasks[0].output_identity,
            allowed_tools=tasks[0].allowed_tools,
        )
        with self.assertRaises(ValueError):
            ExecutableStaticRegistry(
                tasks=(*tasks[:-1], graph_duplicate),
                registry_sha256=self.registry.registry_sha256,
                suite_sha256=self.registry.suite_sha256,
            )
        for mutation in ({"public": False}, {"sealed": True}, {"claim_authorized": True}):
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(ValueError, "claim boundary"):
                    replace(self.registry, **mutation)

    def test_registry_recomputes_and_rejects_forged_content_addresses(self) -> None:
        with self.assertRaisesRegex(ValueError, "registry_sha256 does not match"):
            replace(self.registry, registry_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "suite_sha256 does not match"):
            replace(self.registry, suite_sha256="1" * 64)

    def test_frozen_contracts_reject_mutable_task_and_fixture_containers(self) -> None:
        task = self.registry.tasks[0]
        with self.assertRaisesRegex(ValueError, "fixtures must be an exact tuple"):
            replace(task, fixtures=list(task.fixtures))  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "tasks must be an exact tuple"):
            replace(self.registry, tasks=list(self.registry.tasks))  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "tasks must be an exact tuple"):
            compute_registry_sha256(list(self.registry.tasks))  # type: ignore[arg-type]

    def test_low_level_nested_mutation_is_revalidated_at_public_boundaries(self) -> None:
        original = self.registry.tasks[0]

        standalone = replace(original)
        object.__setattr__(standalone, "task_id", "mds-" + "0" * 24)
        with self.assertRaisesRegex(ValueError, "task_id"):
            standalone.to_public_record()

        parameter = replace(original.parameters)
        descriptors = tuple(replace(item) for item in original.fixtures)
        task = replace(original, parameters=parameter, fixtures=descriptors)
        object.__setattr__(parameter, "label_key", "forged")
        with self.assertRaisesRegex(ValueError, "closed-contract value"):
            task.__post_init__()

        parameter = replace(original.parameters)
        descriptors = tuple(replace(item) for item in original.fixtures)
        task = replace(original, parameters=parameter, fixtures=descriptors)
        object.__setattr__(descriptors[0], "fixture_id", "fx-" + "0" * 24)
        with self.assertRaisesRegex(ValueError, "derived from fixture_sha256"):
            task.__post_init__()

        registry = replace(self.registry)
        tasks = (task, *registry.tasks[1:])
        object.__setattr__(registry, "tasks", tasks)
        with self.assertRaises(ValueError):
            registry.to_public_projection()

    def test_closed_contract_rejects_fixture_and_graph_node_subclasses(self) -> None:
        task = self.registry.tasks[0]

        class DescriptorSubclass(OpaqueFixtureDescriptor):
            pass

        descriptor = task.fixtures[0]
        subclassed_descriptor = DescriptorSubclass(
            fixture_id=descriptor.fixture_id,
            fixture_sha256=descriptor.fixture_sha256,
            task_contract_sha256=descriptor.task_contract_sha256,
        )
        with self.assertRaisesRegex(ValueError, "opaque fixture descriptors"):
            replace(
                task,
                fixtures=(subclassed_descriptor, *task.fixtures[1:]),
            )

        class NodeSubclass(OperatorNode):
            pass

        first_node = task.graph.nodes[0]
        graph = NormalizedSemanticGraph(
            nodes=(
                NodeSubclass(first_node.name, first_node.parameters),
                *task.graph.nodes[1:],
            ),
            dependencies=task.graph.dependencies,
        )
        with self.assertRaisesRegex(ValueError, "exact OperatorNode"):
            replace(task, graph=graph)

    def test_task_contract_rejects_mutable_graph_containers(self) -> None:
        task = self.registry.tasks[0]
        mutable_graphs = (
            NormalizedSemanticGraph(
                nodes=list(task.graph.nodes),  # type: ignore[arg-type]
                dependencies=task.graph.dependencies,
            ),
            NormalizedSemanticGraph(
                nodes=task.graph.nodes,
                dependencies=list(task.graph.dependencies),  # type: ignore[arg-type]
            ),
            NormalizedSemanticGraph(
                nodes=(
                    OperatorNode(
                        task.graph.nodes[0].name,
                        list(task.graph.nodes[0].parameters),  # type: ignore[arg-type]
                    ),
                    *task.graph.nodes[1:],
                ),
                dependencies=task.graph.dependencies,
            ),
        )
        for graph in mutable_graphs:
            with self.subTest(graph=graph), self.assertRaisesRegex(
                ValueError, "exact tuple"
            ):
                replace(task, graph=graph)

    def test_family_schema_rejects_cross_family_contract_fields(self) -> None:
        active = next(
            task
            for task in self.registry.tasks
            if task.family_id == "active-jsonl-labels"
        )
        manifest_copy = next(
            task
            for task in self.registry.tasks
            if task.family_id == "manifest-copy"
        )
        common = {
            "family_id": active.family_id,
            "family_version": active.family_version,
            "parameters": active.parameters,
            "prompt": active.prompt,
            "graph": active.graph,
            "filesystem_identity": active.filesystem_identity,
            "output_identity": active.output_identity,
            "allowed_tools": active.allowed_tools,
        }
        mismatches = (
            {"parameters": manifest_copy.parameters},
            {"filesystem_identity": manifest_copy.filesystem_identity},
            {"output_identity": manifest_copy.output_identity},
            {"allowed_tools": ("find", "sort")},
            {"family_version": "2.0.0"},
        )
        for mismatch in mismatches:
            fields = {**common, **mismatch}
            with self.subTest(mismatch=mismatch), self.assertRaisesRegex(
                ValueError, "closed family schema"
            ):
                compute_task_contract_sha256(**fields)  # type: ignore[arg-type]


class PromptAndIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = build_public_method_development_registry()

    def test_prompts_are_complete_family_specific_program_contracts(self) -> None:
        required = {
            "active-jsonl-labels": ("input/records/", "output/labels.txt", "JSON"),
            "manifest-copy": ("input/copy-map.jsonl", "input/files/", "destination"),
            "csv-group-totals": ("input/records/", "output/totals.csv", "RFC 4180"),
            "checksum-manifest": ("input/manifest.data", "input/assets/", "output/report.jsonl"),
            "path-suffix-inventory": ("input/tree/", "output/paths.txt", "LC_ALL=C"),
        }
        for task in self.registry.tasks:
            normalized = " ".join(task.prompt.split())
            self.assertTrue(task.prompt.startswith("Write one Bash program"))
            self.assertIn("without following symbolic links", normalized)
            self.assertIn("Preserve every path", normalized)
            self.assertIn("Use only Bash built-ins plus", normalized)
            self.assertIn("mkdir", task.allowed_tools)
            self.assertIn("`mkdir`", task.prompt)
            for fragment in required[task.family_id]:
                self.assertIn(fragment, task.prompt)

    def test_filesystem_output_and_tool_identities_are_family_exact(self) -> None:
        expected = {
            "active-jsonl-labels": (
                "structured-records-tree-v1",
                "utf8-byte-sorted-lines-v1",
                ("find", "jq", "mkdir", "sort"),
            ),
            "manifest-copy": (
                "symlinked-copy-workspace-v1",
                "exact-output-tree-v1",
                ("cp", "jq", "mkdir", "sha256sum"),
            ),
            "csv-group-totals": (
                "structured-csv-tree-v1",
                "rfc4180-group-totals-v1",
                ("awk", "mkdir", "sort"),
            ),
            "checksum-manifest": (
                "permission-boundary-assets-v1",
                "jsonl-checksum-status-v1",
                ("awk", "jq", "mkdir", "sha256sum", "sort", "stat"),
            ),
            "path-suffix-inventory": (
                "nested-project-tree-v1",
                "utf8-byte-sorted-paths-v1",
                ("find", "mkdir", "sort"),
            ),
        }
        for task in self.registry.tasks:
            self.assertEqual(
                (
                    task.filesystem_identity,
                    task.output_identity,
                    task.allowed_tools,
                ),
                expected[task.family_id],
            )


class OpaqueFixtureAndProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = build_public_method_development_registry()

    def test_fixture_descriptors_bind_real_definition_and_oracle_content(self) -> None:
        for task in self.registry.tasks:
            for descriptor, profile in zip(
                task.fixtures,
                PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
                strict=True,
            ):
                bundle = build_fixture_bundle_for_task_profile(
                    task, profile
                )
                self.assertEqual(descriptor, bundle.descriptor)
                self.assertEqual(
                    descriptor.task_contract_sha256, task.task_contract_sha256
                )

    def test_fixture_public_records_are_strictly_opaque(self) -> None:
        for task in self.registry.tasks:
            for descriptor in task.fixtures:
                record = descriptor.to_public_record()
                self.assertEqual(
                    set(record),
                    {
                        "schema_version",
                        "fixture_id",
                        "fixture_sha256",
                        "task_contract_sha256",
                    },
                )
                serialized = json.dumps(record, sort_keys=True)
                for forbidden in (
                    "seed",
                    "profile",
                    "cases",
                    "answer",
                    "expected",
                    "input/",
                    "output/",
                ):
                    self.assertNotIn(forbidden, serialized)

    def test_descriptor_rejects_cross_task_or_malformed_identity(self) -> None:
        first, second = self.registry.tasks[:2]
        descriptor = first.fixtures[0]
        with self.assertRaises(ValueError):
            replace(descriptor, fixture_id="fx-visible-0")
        crossed = OpaqueFixtureDescriptor(
            fixture_id=descriptor.fixture_id,
            fixture_sha256=descriptor.fixture_sha256,
            task_contract_sha256=second.task_contract_sha256,
        )
        with self.assertRaisesRegex(ValueError, "different task"):
            replace(first, fixtures=(crossed, *first.fixtures[1:]))

    def test_public_projection_is_nonsealed_nonclaiming_and_has_no_fixture_metadata(self) -> None:
        projection = self.registry.to_public_projection()
        self.assertEqual(projection["split_role"], "method_development")
        self.assertTrue(projection["public"])
        self.assertFalse(projection["sealed"])
        self.assertFalse(projection["claim_authorized"])
        self.assertEqual(projection["task_count"], 100)
        self.assertEqual(projection["fixture_count"], 500)
        self.assertEqual(projection["fixtures_per_task"], 5)
        encoded = json.dumps(projection, sort_keys=True)
        for forbidden_key in (
            '"fixture_seed"',
            '"profile_sha256"',
            '"edge_case_tags"',
            '"expected_answer"',
            '"fixture_path"',
        ):
            self.assertNotIn(forbidden_key, encoded)

    def test_projection_copy_cannot_mutate_registry(self) -> None:
        projection = self.registry.to_public_projection()
        mutated = copy.deepcopy(projection)
        mutated["tasks"][0]["prompt"] = "changed"  # type: ignore[index]
        self.assertNotEqual(projection, mutated)
        self.assertNotEqual(
            self.registry.tasks[0].prompt,
            mutated["tasks"][0]["prompt"],  # type: ignore[index]
        )


if __name__ == "__main__":
    unittest.main()
