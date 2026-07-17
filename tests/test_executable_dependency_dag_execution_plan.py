from __future__ import annotations

import ast
import copy
from dataclasses import replace
import json
import os
from pathlib import Path
import random
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_dependency_dag_execution_plan as dag_module
from cbds.benchmark import NormalizedSemanticGraph, OperatorNode
from cbds.executable_dependency_dag_execution_plan import (
    DEPENDENCY_DAG_EXECUTION_PLAN_ALLOWED_TOOLS,
    DEPENDENCY_DAG_EXECUTION_PLAN_ATOMICITY_OBSERVED,
    DEPENDENCY_DAG_EXECUTION_PLAN_CANDIDATE_EXIT_STATUS_OBSERVED,
    DEPENDENCY_DAG_EXECUTION_PLAN_FAMILY_ID,
    DEPENDENCY_DAG_EXECUTION_PLAN_FINAL_OUTPUT_OBSERVED,
    DEPENDENCY_DAG_EXECUTION_PLAN_GRAPH_ENCODINGS,
    DEPENDENCY_DAG_EXECUTION_PLAN_INPUT,
    DEPENDENCY_DAG_EXECUTION_PLAN_INPUT_PRESERVATION_OBSERVED,
    DEPENDENCY_DAG_EXECUTION_PLAN_JSON_MAXIMUM_DEPTH,
    DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_EDGES,
    DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_NODES,
    DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_PHYSICAL_DEPENDENCIES,
    DEPENDENCY_DAG_EXECUTION_PLAN_NODE_ID_MAXIMUM_UTF8_BYTES,
    DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT,
    DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_MAXIMUM_BYTES,
    DEPENDENCY_DAG_EXECUTION_PLAN_PRIORITY_MAXIMUM,
    DEPENDENCY_DAG_EXECUTION_PLAN_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES,
    DEPENDENCY_DAG_EXECUTION_PLAN_READ_SCOPE_OBSERVED,
    DEPENDENCY_DAG_EXECUTION_PLAN_SOURCE_MAXIMUM_BYTES,
    DEPENDENCY_DAG_EXECUTION_PLAN_TIE_BREAK_POLICIES,
    DEPENDENCY_DAG_EXECUTION_PLAN_TOOL_HISTORY_OBSERVED,
    DEPENDENCY_DAG_EXECUTION_PLAN_TRANSIENT_STATE_OBSERVED,
    DEPENDENCY_DAG_EXECUTION_PLAN_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
    DEPENDENCY_DAG_EXECUTION_PLAN_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE,
    DependencyDag,
    DependencyDagExecutionPlanError,
    DependencyDagExecutionPlanParameters,
    DependencyDagNode,
    build_dependency_dag_execution_plan_fixture_bundle,
    build_dependency_dag_execution_plan_tasks,
    compute_dependency_dag_execution_plan_discrimination_sha256,
    compute_dependency_dag_execution_plan_proved_output_bound,
    dependency_dag_execution_plan_task_semantic_core,
    derive_dependency_dag_execution_plan_state,
    materialize_dependency_dag_execution_plan_fixture,
    parse_dependency_dag_execution_plan_output,
    parse_dependency_dag_execution_plan_source,
    reference_dependency_dag_execution_plan_state,
    validate_dependency_dag_execution_plan_fixture_bundle,
    validate_dependency_dag_execution_plan_fixture_for_task_profile,
    verify_dependency_dag_execution_plan_fixture_bundle,
    verify_dependency_dag_execution_plan_fixture_for_task_profile,
    verify_dependency_dag_execution_plan_workspace,
)
from cbds.executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_static_types import OpaqueFixtureDescriptor
from cbds.executable_workspace import (
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
    MAX_TOTAL_BYTES,
)


TASKS = build_dependency_dag_execution_plan_tasks()
TASK_BY_CELL = {
    (
        task.parameters.graph_encoding,
        task.parameters.tie_break_policy,
    ): task
    for task in TASKS
}
PROFILE_BY_ID = {
    profile.profile_id: profile
    for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
}
EXPECTED_DISCRIMINATION_SHA256 = (
    "25c9f68985ed918a6e8fe9d36b4b6d8a9bd34bb2cd9b039dff82a9276658c82c"
)


def _json_bytes(value: object, *, canonical: bool = True) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=canonical,
            separators=(",", ":") if canonical else (", ", ": "),
        ).encode("utf-8")
        + b"\n"
    )


def _adjacency(
    nodes: list[dict[str, object]] | None = None,
) -> bytes:
    if nodes is None:
        nodes = [
            {"id": "a", "priority": 0, "depends_on": []},
            {"id": "b", "priority": 1, "depends_on": ["a"]},
        ]
    return _json_bytes({"nodes": nodes})


def _definition(
    payload: bytes,
    *,
    mode: int = 0o600,
) -> FixtureDefinition:
    return FixtureDefinition(
        "fixture.dependency-dag-example",
        (
            InputFile(
                DEPENDENCY_DAG_EXECUTION_PLAN_INPUT,
                payload,
                mode,
                100,
            ),
        ),
        (),
    )


def _write_state(handle: object, content: bytes) -> None:
    output = handle.workspace / "output"
    output.mkdir(parents=True, exist_ok=True)
    output.chmod(0o755)
    path = handle.workspace / DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT
    path.write_bytes(content)
    path.chmod(0o644)


class DependencyDagExecutionPlanTaskTests(unittest.TestCase):
    def test_grid_is_exact_unique_public_and_discriminable(self) -> None:
        expected = tuple(
            (encoding, policy)
            for encoding in DEPENDENCY_DAG_EXECUTION_PLAN_GRAPH_ENCODINGS
            for policy in DEPENDENCY_DAG_EXECUTION_PLAN_TIE_BREAK_POLICIES
        )
        self.assertEqual(len(TASKS), 20)
        self.assertEqual(
            tuple(
                (
                    task.parameters.graph_encoding,
                    task.parameters.tie_break_policy,
                )
                for task in TASKS
            ),
            expected,
        )
        self.assertEqual(len({task.task_id for task in TASKS}), 20)
        self.assertEqual(
            len({task.task_contract_sha256 for task in TASKS}), 20
        )
        self.assertEqual(len({task.graph_sha256 for task in TASKS}), 20)
        self.assertEqual(
            compute_dependency_dag_execution_plan_discrimination_sha256(
                TASKS
            ),
            EXPECTED_DISCRIMINATION_SHA256,
        )
        for task in TASKS:
            with self.subTest(task=task.task_id):
                task.__post_init__()
                self.assertEqual(
                    task.family_id,
                    DEPENDENCY_DAG_EXECUTION_PLAN_FAMILY_ID,
                )
                self.assertEqual(
                    task.allowed_tools,
                    DEPENDENCY_DAG_EXECUTION_PLAN_ALLOWED_TOOLS,
                )
                self.assertEqual(len(task.fixtures), 5)
                self.assertTrue(task.public)
                self.assertFalse(task.sealed)
                self.assertFalse(task.candidate_execution_authorized)
                self.assertFalse(task.model_selection_eligible)
                self.assertFalse(task.claim_authorized)
                semantic = dependency_dag_execution_plan_task_semantic_core(
                    task.parameters, task.prompt, task.graph
                )
                self.assertEqual(
                    semantic["family_id"],
                    DEPENDENCY_DAG_EXECUTION_PLAN_FAMILY_ID,
                )
                self.assertIn(
                    "Duplicate node declarations and unknown endpoints are invalid",
                    task.prompt.replace("\n", " "),
                )
                self.assertIn(
                    "one to 64 declared nodes",
                    task.prompt.replace("\n", " "),
                )
                self.assertIn(
                    "cannot prove tool use, Python module or syscall confinement",
                    task.prompt.replace("\n", " "),
                )

    def test_task_and_authority_mutations_fail_closed(self) -> None:
        task = TASKS[0]
        with self.assertRaises(DependencyDagExecutionPlanError):
            DependencyDagExecutionPlanParameters(  # type: ignore[arg-type]
                "invented", "utf8-smallest"
            )
        with self.assertRaises(DependencyDagExecutionPlanError):
            DependencyDagExecutionPlanParameters(  # type: ignore[arg-type]
                "json-adjacency", "invented"
            )
        with self.assertRaises(DependencyDagExecutionPlanError):
            replace(task, prompt=task.prompt + " ")
        with self.assertRaises(DependencyDagExecutionPlanError):
            replace(task, candidate_execution_authorized=True)
        with self.assertRaises(DependencyDagExecutionPlanError):
            replace(task, allowed_tools=task.allowed_tools + ("sort",))
        with self.assertRaises(DependencyDagExecutionPlanError):
            replace(task, fixtures=(task.fixtures[0],) * 5)

    def test_observation_boundary_and_no_production_asserts(self) -> None:
        self.assertTrue(
            DEPENDENCY_DAG_EXECUTION_PLAN_FINAL_OUTPUT_OBSERVED
        )
        self.assertTrue(
            DEPENDENCY_DAG_EXECUTION_PLAN_INPUT_PRESERVATION_OBSERVED
        )
        self.assertTrue(
            DEPENDENCY_DAG_EXECUTION_PLAN_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE
        )
        for value in (
            DEPENDENCY_DAG_EXECUTION_PLAN_ATOMICITY_OBSERVED,
            DEPENDENCY_DAG_EXECUTION_PLAN_TOOL_HISTORY_OBSERVED,
            DEPENDENCY_DAG_EXECUTION_PLAN_READ_SCOPE_OBSERVED,
            DEPENDENCY_DAG_EXECUTION_PLAN_CANDIDATE_EXIT_STATUS_OBSERVED,
            DEPENDENCY_DAG_EXECUTION_PLAN_TRANSIENT_STATE_OBSERVED,
            DEPENDENCY_DAG_EXECUTION_PLAN_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
        ):
            self.assertFalse(value)
        source_path = (
            ROOT
            / "src"
            / "cbds"
            / "executable_dependency_dag_execution_plan.py"
        )
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        self.assertFalse(
            any(isinstance(node, ast.Assert) for node in ast.walk(tree))
        )


class DependencyDagExecutionPlanPolicyTests(unittest.TestCase):
    def test_all_five_policies_have_exact_distinct_orders(self) -> None:
        profile = PROFILE_BY_ID["spaces-unicode"]
        observed: dict[str, tuple[str, ...]] = {}
        for policy in DEPENDENCY_DAG_EXECUTION_PLAN_TIE_BREAK_POLICIES:
            task = TASK_BY_CELL[("json-adjacency", policy)]
            bundle = build_dependency_dag_execution_plan_fixture_bundle(
                task, profile
            )
            state = bundle.oracle.state
            self.assertEqual(state.status, "valid")
            self.assertEqual(state.blocked_nodes, ())
            self.assertEqual(state.cyclic_nodes, ())
            observed[policy] = state.plan
        self.assertEqual(len(set(observed.values())), 5)
        self.assertEqual(observed["utf8-smallest"][:2], (
            "a root",
            '-child "quoted" \\ literal',
        ))
        self.assertEqual(
            observed["declared-priority"][0], "p priority"
        )
        self.assertEqual(
            observed["shortest-depth"][:4],
            ("a root", "f fanout 雪", "p priority", "z stable"),
        )
        self.assertEqual(observed["largest-fanout"][0], "f fanout 雪")
        self.assertEqual(observed["stable-input-order"][:4], (
            "z stable",
            "f fanout 雪",
            "p priority",
            "a root",
        ))

    def test_depth_is_longest_prerequisite_depth_not_shortest_path(
        self,
    ) -> None:
        # target has both a direct root edge and a length-two prerequisite
        # chain.  Its required depth is therefore two, not one.
        payload = _adjacency(
            [
                {"id": "z-root", "priority": 0, "depends_on": []},
                {"id": "a-mid", "priority": 0, "depends_on": ["z-root"]},
                {
                    "id": "-target",
                    "priority": 0,
                    "depends_on": ["z-root", "a-mid"],
                },
                {"id": "b-depth-one", "priority": 0, "depends_on": ["z-root"]},
            ]
        )
        parameters = DependencyDagExecutionPlanParameters(
            "json-adjacency", "shortest-depth"
        )
        primary = derive_dependency_dag_execution_plan_state(
            _definition(payload), parameters
        )
        reference = reference_dependency_dag_execution_plan_state(
            _definition(payload), parameters
        )
        self.assertEqual(primary, reference)
        self.assertEqual(
            primary.plan,
            ("z-root", "a-mid", "b-depth-one", "-target"),
        )

    def test_cycle_clears_partial_plan_and_separates_blocked_from_cyclic(
        self,
    ) -> None:
        profile = PROFILE_BY_ID["partial-permissions"]
        for policy in DEPENDENCY_DAG_EXECUTION_PLAN_TIE_BREAK_POLICIES:
            task = TASK_BY_CELL[("json-edge-list", policy)]
            state = build_dependency_dag_execution_plan_fixture_bundle(
                task, profile
            ).oracle.state
            with self.subTest(policy=policy):
                self.assertEqual(state.status, "cycle")
                self.assertEqual(state.plan, ())
                self.assertEqual(
                    state.blocked_nodes,
                    (
                        "cycle-a",
                        "cycle-b",
                        "downstream blocked",
                        "self-loop",
                    ),
                )
                self.assertEqual(
                    state.cyclic_nodes,
                    ("cycle-a", "cycle-b", "self-loop"),
                )
                self.assertEqual(state.edge_count, 5)

    def test_primary_and_reference_planners_are_algorithmically_independent(
        self,
    ) -> None:
        dag_definition = _definition(
            _adjacency(
                [
                    {"id": "z", "priority": 0, "depends_on": []},
                    {"id": "a", "priority": 2, "depends_on": []},
                    {"id": "b", "priority": 1, "depends_on": ["a"]},
                ]
            )
        )
        parameters = DependencyDagExecutionPlanParameters(
            "json-adjacency", "shortest-depth"
        )
        expected_reference = reference_dependency_dag_execution_plan_state(
            dag_definition, parameters
        )
        with (
            mock.patch.object(
                dag_module,
                "_graph_maps",
                side_effect=RuntimeError("primary map used"),
            ),
            mock.patch.object(
                dag_module,
                "_selection_key",
                side_effect=RuntimeError("primary key used"),
            ),
            mock.patch.object(
                dag_module,
                "_derive_primary_plan",
                side_effect=RuntimeError("primary planner used"),
            ),
            mock.patch.object(
                dag_module,
                "_cyclic_nodes_by_return_reachability",
                side_effect=RuntimeError("primary cycle helper used"),
            ),
        ):
            self.assertEqual(
                reference_dependency_dag_execution_plan_state(
                    dag_definition, parameters
                ),
                expected_reference,
            )

        expected_primary = derive_dependency_dag_execution_plan_state(
            dag_definition, parameters
        )
        with (
            mock.patch.object(
                dag_module,
                "_reference_kahn_residual",
                side_effect=RuntimeError("reference residual used"),
            ),
            mock.patch.object(
                dag_module,
                "_reference_cyclic_nodes",
                side_effect=RuntimeError("reference cycle used"),
            ),
            mock.patch.object(
                dag_module,
                "_reference_depths",
                side_effect=RuntimeError("reference depth used"),
            ),
            mock.patch.object(
                dag_module,
                "_reference_selection_key",
                side_effect=RuntimeError("reference key used"),
            ),
            mock.patch.object(
                dag_module,
                "_derive_reference_plan",
                side_effect=RuntimeError("reference planner used"),
            ),
        ):
            self.assertEqual(
                derive_dependency_dag_execution_plan_state(
                    dag_definition, parameters
                ),
                expected_primary,
            )

    def test_discrimination_uses_behavior_not_echoed_axis_labels(self) -> None:
        profile = PROFILE_BY_ID["spaces-unicode"]
        states = tuple(
            build_dependency_dag_execution_plan_fixture_bundle(
                TASK_BY_CELL[("json-adjacency", policy)], profile
            ).oracle.state
            for policy in DEPENDENCY_DAG_EXECUTION_PLAN_TIE_BREAK_POLICIES
        )
        behavioral_hashes = tuple(
            dag_module._outcome_sha256(state) for state in states
        )
        self.assertEqual(len(set(behavioral_hashes)), 5)

        original = states[0]
        changed_value = original.to_value()
        changed_value["graph_encoding"] = "json-edge-list"
        changed_value["tie_break_policy"] = "stable-input-order"
        echoed_only = replace(
            original,
            graph_encoding="json-edge-list",
            tie_break_policy="stable-input-order",
            content=_json_bytes(changed_value),
        )
        self.assertNotEqual(original.content, echoed_only.content)
        self.assertEqual(
            dag_module._outcome_sha256(original),
            dag_module._outcome_sha256(echoed_only),
        )

    def test_deterministic_random_graphs_agree_across_both_oracles(
        self,
    ) -> None:
        generator = random.Random(20_260_717)
        saw_valid = False
        saw_cycle = False
        for case_index in range(160):
            size = generator.randint(1, 9)
            identifiers = [f"node-{index}" for index in range(size)]
            nodes: list[dict[str, object]] = []
            for dependent_index, node_id in enumerate(identifiers):
                dependencies = [
                    prerequisite
                    for prerequisite in identifiers
                    if generator.random() < 0.19
                ]
                if dependencies and generator.random() < 0.35:
                    dependencies.append(generator.choice(dependencies))
                nodes.append(
                    {
                        "id": node_id,
                        "priority": generator.randint(-20, 20),
                        "depends_on": dependencies,
                    }
                )
            definition = _definition(_adjacency(nodes))
            for policy in DEPENDENCY_DAG_EXECUTION_PLAN_TIE_BREAK_POLICIES:
                parameters = DependencyDagExecutionPlanParameters(
                    "json-adjacency", policy
                )
                primary = derive_dependency_dag_execution_plan_state(
                    definition, parameters
                )
                reference = reference_dependency_dag_execution_plan_state(
                    definition, parameters
                )
                with self.subTest(case=case_index, policy=policy):
                    self.assertEqual(primary, reference)
                saw_valid = saw_valid or primary.status == "valid"
                saw_cycle = saw_cycle or primary.status == "cycle"
        self.assertTrue(saw_valid)
        self.assertTrue(saw_cycle)


class DependencyDagExecutionPlanSourceTests(unittest.TestCase):
    def test_all_encodings_represent_identical_profile_graphs(self) -> None:
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
            graphs = []
            for encoding in DEPENDENCY_DAG_EXECUTION_PLAN_GRAPH_ENCODINGS:
                task = TASK_BY_CELL[(encoding, "utf8-smallest")]
                bundle = build_dependency_dag_execution_plan_fixture_bundle(
                    task, profile
                )
                source = next(
                    item.content
                    for item in bundle.definition.inputs
                    if type(item) is InputFile
                    and item.path == DEPENDENCY_DAG_EXECUTION_PLAN_INPUT
                )
                graph = parse_dependency_dag_execution_plan_source(
                    source, encoding
                )
                graphs.append(graph)
            with self.subTest(profile=profile.profile_id):
                self.assertTrue(all(graph == graphs[0] for graph in graphs))

    def test_csv_is_crlf_interleaved_and_rfc4180_quoted(self) -> None:
        task = TASK_BY_CELL[("csv-edges", "utf8-smallest")]
        bundle = build_dependency_dag_execution_plan_fixture_bundle(
            task, PROFILE_BY_ID["spaces-unicode"]
        )
        source = next(
            item.content
            for item in bundle.definition.inputs
            if type(item) is InputFile
            and item.path == DEPENDENCY_DAG_EXECUTION_PLAN_INPUT
        )
        self.assertTrue(source.endswith(b"\r\n"))
        self.assertNotIn(b"\n", source.replace(b"\r\n", b""))
        self.assertIn(b'"-child ""quoted""', source)
        lines = source.split(b"\r\n")
        first_edge = next(
            index for index, line in enumerate(lines) if line.startswith(b"edge,")
        )
        last_node = max(
            index for index, line in enumerate(lines) if line.startswith(b"node,")
        )
        self.assertLess(first_edge, last_node)

    def test_duplicate_edges_are_idempotent_in_every_encoding(self) -> None:
        payloads = {
            "json-adjacency": _json_bytes(
                {
                    "nodes": [
                        {"id": "a", "priority": 0, "depends_on": []},
                        {
                            "id": "b",
                            "priority": 0,
                            "depends_on": ["a", "a"],
                        },
                    ]
                }
            ),
            "json-edge-list": _json_bytes(
                {
                    "nodes": [
                        {"id": "a", "priority": 0},
                        {"id": "b", "priority": 0},
                    ],
                    "edges": [
                        {"dependent": "b", "prerequisite": "a"},
                        {"dependent": "b", "prerequisite": "a"},
                    ],
                }
            ),
            "csv-edges": (
                b"record,node,priority,dependency\r\n"
                b"edge,b,,a\r\n"
                b"node,a,0,\r\n"
                b"node,b,0,\r\n"
                b"edge,b,,a\r\n"
            ),
            "line-oriented-dependencies": b"0\ta\n0\tb\ta\ta\n",
        }
        for encoding, payload in payloads.items():
            with self.subTest(encoding=encoding):
                graph = parse_dependency_dag_execution_plan_source(
                    payload, encoding  # type: ignore[arg-type]
                )
                self.assertEqual(graph.edge_count, 1)
                self.assertEqual(graph.nodes[1].prerequisites, ("a",))

    def test_zero_node_graph_is_rejected_in_every_encoding(self) -> None:
        payloads = {
            "json-adjacency": _json_bytes({"nodes": []}),
            "json-edge-list": _json_bytes({"nodes": [], "edges": []}),
            "csv-edges": b"record,node,priority,dependency\r\n",
            "line-oriented-dependencies": b"",
        }
        for encoding, payload in payloads.items():
            with self.subTest(encoding=encoding):
                with self.assertRaises(DependencyDagExecutionPlanError):
                    parse_dependency_dag_execution_plan_source(
                        payload, encoding  # type: ignore[arg-type]
                    )

    def test_duplicate_nodes_unknown_endpoints_and_invalid_ids_fail(
        self,
    ) -> None:
        cases = (
            _adjacency(
                [
                    {"id": "a", "priority": 0, "depends_on": []},
                    {"id": "a", "priority": 1, "depends_on": []},
                ]
            ),
            _adjacency(
                [{"id": "a", "priority": 0, "depends_on": ["missing"]}]
            ),
            _adjacency(
                [{"id": "", "priority": 0, "depends_on": []}]
            ),
            _adjacency(
                [{"id": "bad\u200bname", "priority": 0, "depends_on": []}]
            ),
            _adjacency(
                [{"id": "bad\nname", "priority": 0, "depends_on": []}]
            ),
            _adjacency(
                [
                    {
                        "id": "x"
                        * (
                            DEPENDENCY_DAG_EXECUTION_PLAN_NODE_ID_MAXIMUM_UTF8_BYTES
                            + 1
                        ),
                        "priority": 0,
                        "depends_on": [],
                    }
                ]
            ),
        )
        for payload in cases:
            with self.subTest(payload=payload[:80]):
                with self.assertRaises(DependencyDagExecutionPlanError):
                    parse_dependency_dag_execution_plan_source(
                        payload, "json-adjacency"
                    )

    def test_priority_exact_types_and_boundaries(self) -> None:
        accepted = (
            -DEPENDENCY_DAG_EXECUTION_PLAN_PRIORITY_MAXIMUM,
            0,
            DEPENDENCY_DAG_EXECUTION_PLAN_PRIORITY_MAXIMUM,
        )
        for priority in accepted:
            graph = parse_dependency_dag_execution_plan_source(
                _adjacency(
                    [{"id": "a", "priority": priority, "depends_on": []}]
                ),
                "json-adjacency",
            )
            self.assertEqual(graph.nodes[0].priority, priority)
        for priority in (
            True,
            DEPENDENCY_DAG_EXECUTION_PLAN_PRIORITY_MAXIMUM + 1,
            -DEPENDENCY_DAG_EXECUTION_PLAN_PRIORITY_MAXIMUM - 1,
        ):
            with self.subTest(priority=priority):
                with self.assertRaises(DependencyDagExecutionPlanError):
                    parse_dependency_dag_execution_plan_source(
                        _adjacency(
                            [
                                {
                                    "id": "a",
                                    "priority": priority,
                                    "depends_on": [],
                                }
                            ]
                        ),
                        "json-adjacency",
                    )
        for token in (b"01", b"-0", b"+1", b"1.0", b"1000001"):
            with self.subTest(token=token):
                payload = b"".join((token, b"\ta\n"))
                with self.assertRaises(DependencyDagExecutionPlanError):
                    parse_dependency_dag_execution_plan_source(
                        payload, "line-oriented-dependencies"
                    )

    def test_json_closed_schema_duplicates_and_framing_fail(self) -> None:
        malformed = (
            b'{"nodes":[],"nodes":[]}\n',
            b'{"nodes":[],"extra":1}\n',
            b'{"nodes":[{"id":"a","priority":0}]}\n',
            b'{"nodes":[{"depends_on":[],"id":"a","priority":0.0}]}\n',
            b'{"nodes":[{"depends_on":[],"id":"a","priority":NaN}]}\n',
            b"\xef\xbb\xbf" + _adjacency(),
            _adjacency()[:-1],
            _adjacency() + b"\n",
            _adjacency().replace(b"\n", b"\r\n"),
            b"[" * (DEPENDENCY_DAG_EXECUTION_PLAN_JSON_MAXIMUM_DEPTH + 1)
            + b"0"
            + b"]" * (DEPENDENCY_DAG_EXECUTION_PLAN_JSON_MAXIMUM_DEPTH + 1)
            + b"\n",
        )
        for payload in malformed:
            with self.subTest(payload=payload[:60]):
                with self.assertRaises(DependencyDagExecutionPlanError):
                    parse_dependency_dag_execution_plan_source(
                        payload, "json-adjacency"
                    )

    def test_csv_and_line_closed_grammars_fail(self) -> None:
        malformed_csv = (
            b"record,node,priority,dependency\nnode,a,0,\n",
            b"record,node,priority,dependency\r\nnode,a,0,\n",
            b"\xef\xbb\xbfrecord,node,priority,dependency\r\nnode,a,0,\r\n",
            b"record,node,priority,dependency\r\nnode,a,0,x\r\n",
            b"record,node,priority,dependency\r\nedge,a,1,a\r\n",
            b"record,node,priority,dependency\r\ninvented,a,0,\r\n",
            b"record,node,priority,wrong\r\nnode,a,0,\r\n",
            (
                b"record,node,priority,dependency\r\n"
                b'node,a"b,0,\r\n'
            ),
            (
                b"record,node,priority,dependency\r\n"
                b'node,"a"x,0,\r\n'
            ),
        )
        for payload in malformed_csv:
            with self.subTest(payload=payload):
                with self.assertRaises(DependencyDagExecutionPlanError):
                    parse_dependency_dag_execution_plan_source(
                        payload, "csv-edges"
                    )
        malformed_lines = (
            b"0\ta",
            b"0\ta\r\n",
            b"\n",
            b"0\n",
            b"0\ta\t\n",
            b"\xef\xbb\xbf0\ta\n",
        )
        for payload in malformed_lines:
            with self.subTest(payload=payload):
                with self.assertRaises(DependencyDagExecutionPlanError):
                    parse_dependency_dag_execution_plan_source(
                        payload, "line-oriented-dependencies"
                    )

    def test_node_physical_edge_and_source_bounds_are_exact(self) -> None:
        accepted_nodes = [
            {"id": f"n-{index:02d}", "priority": 0, "depends_on": []}
            for index in range(
                DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_NODES
            )
        ]
        graph = parse_dependency_dag_execution_plan_source(
            _adjacency(accepted_nodes), "json-adjacency"
        )
        self.assertEqual(
            len(graph.nodes), DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_NODES
        )
        with self.assertRaises(DependencyDagExecutionPlanError):
            parse_dependency_dag_execution_plan_source(
                _adjacency(
                    accepted_nodes
                    + [{"id": "one-too-many", "priority": 0, "depends_on": []}]
                ),
                "json-adjacency",
            )

        duplicates = ["a"] * (
            DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_PHYSICAL_DEPENDENCIES
        )
        accepted_edges = _adjacency(
            [
                {"id": "a", "priority": 0, "depends_on": []},
                {"id": "b", "priority": 0, "depends_on": duplicates},
            ]
        )
        self.assertEqual(
            parse_dependency_dag_execution_plan_source(
                accepted_edges, "json-adjacency"
            ).edge_count,
            1,
        )
        rejected_edges = _adjacency(
            [
                {"id": "a", "priority": 0, "depends_on": []},
                {"id": "b", "priority": 0, "depends_on": duplicates + ["a"]},
            ]
        )
        with self.assertRaises(DependencyDagExecutionPlanError):
            parse_dependency_dag_execution_plan_source(
                rejected_edges, "json-adjacency"
            )

        compact = _adjacency()
        padding = (
            DEPENDENCY_DAG_EXECUTION_PLAN_SOURCE_MAXIMUM_BYTES - len(compact)
        )
        maximum = compact[:-1] + (b" " * padding) + b"\n"
        self.assertEqual(
            len(maximum),
            DEPENDENCY_DAG_EXECUTION_PLAN_SOURCE_MAXIMUM_BYTES,
        )
        self.assertEqual(
            len(
                parse_dependency_dag_execution_plan_source(
                    maximum, "json-adjacency"
                ).nodes
            ),
            2,
        )
        with self.assertRaises(DependencyDagExecutionPlanError):
            parse_dependency_dag_execution_plan_source(
                maximum[:-1] + b" \n", "json-adjacency"
            )

    def test_distinct_edge_bound_rejects_257_after_coalescing(self) -> None:
        nodes = [
            {"id": f"n-{index:02d}", "priority": 0, "depends_on": []}
            for index in range(24)
        ]
        remaining = DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_EDGES + 1
        for dependent in range(1, 24):
            dependencies = [
                f"n-{prerequisite:02d}"
                for prerequisite in range(dependent)
            ][:remaining]
            nodes[dependent]["depends_on"] = dependencies
            remaining -= len(dependencies)
            if remaining <= 0:
                break
        self.assertEqual(remaining, 0)
        accepted = copy.deepcopy(nodes)
        accepted_dependency = accepted[-1]["depends_on"]
        self.assertIs(type(accepted_dependency), list)
        accepted_dependency.pop()
        self.assertEqual(
            parse_dependency_dag_execution_plan_source(
                _adjacency(accepted), "json-adjacency"
            ).edge_count,
            DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_EDGES,
        )
        with self.assertRaises(DependencyDagExecutionPlanError):
            parse_dependency_dag_execution_plan_source(
                _adjacency(nodes), "json-adjacency"
            )

    def test_multibyte_node_id_utf8_boundary_is_exact(self) -> None:
        boundary = ("雪" * 42) + "ab"
        oversized = boundary + "b"
        self.assertEqual(
            len(boundary.encode("utf-8")),
            DEPENDENCY_DAG_EXECUTION_PLAN_NODE_ID_MAXIMUM_UTF8_BYTES,
        )
        self.assertEqual(
            parse_dependency_dag_execution_plan_source(
                _adjacency(
                    [
                        {
                            "id": boundary,
                            "priority": 0,
                            "depends_on": [],
                        }
                    ]
                ),
                "json-adjacency",
            ).nodes[0].node_id,
            boundary,
        )
        with self.assertRaises(DependencyDagExecutionPlanError):
            parse_dependency_dag_execution_plan_source(
                _adjacency(
                    [
                        {
                            "id": oversized,
                            "priority": 0,
                            "depends_on": [],
                        }
                    ]
                ),
                "json-adjacency",
            )


class DependencyDagExecutionPlanFixtureTests(unittest.TestCase):
    def test_all_100_bundles_reconstruct_with_independent_oracles(self) -> None:
        fixture_ids: set[str] = set()
        count = 0
        for task in TASKS:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                with self.subTest(
                    encoding=task.parameters.graph_encoding,
                    policy=task.parameters.tie_break_policy,
                    profile=profile.profile_id,
                ):
                    bundle = (
                        build_dependency_dag_execution_plan_fixture_bundle(
                            task, profile
                        )
                    )
                    validate_dependency_dag_execution_plan_fixture_bundle(
                        bundle
                    )
                    validate_dependency_dag_execution_plan_fixture_for_task_profile(
                        task, profile, bundle
                    )
                    self.assertTrue(
                        verify_dependency_dag_execution_plan_fixture_bundle(
                            bundle
                        )
                    )
                    self.assertTrue(
                        verify_dependency_dag_execution_plan_fixture_for_task_profile(
                            task, profile, bundle
                        )
                    )
                    primary = derive_dependency_dag_execution_plan_state(
                        bundle.definition, task.parameters
                    )
                    reference = (
                        reference_dependency_dag_execution_plan_state(
                            bundle.definition, task.parameters
                        )
                    )
                    self.assertEqual(primary, reference)
                    self.assertEqual(primary, bundle.oracle.state)
                    self.assertEqual(
                        parse_dependency_dag_execution_plan_output(
                            primary.content
                        ),
                        primary.content,
                    )
                    fixture_ids.add(bundle.descriptor.fixture_sha256)
                    count += 1
        self.assertEqual(count, 100)
        self.assertEqual(len(fixture_ids), 100)

    def test_exact_owned_types_and_binding_mutations_fail_closed(self) -> None:
        class StringSubclass(str):
            pass

        class TupleSubclass(tuple):
            pass

        class StateProxy:
            def __init__(self, state: object) -> None:
                self._state = state

            def __getattr__(self, name: str) -> object:
                return getattr(self._state, name)

            def __eq__(self, other: object) -> bool:
                return self._state == other

            def __post_init__(self) -> None:
                self._state.__post_init__()

        task = TASKS[0]
        for field_name in (
            "family_id",
            "family_version",
            "filesystem_identity",
            "output_identity",
            "split_role",
        ):
            with self.subTest(task_field=field_name):
                with self.assertRaises(DependencyDagExecutionPlanError):
                    replace(
                        task,
                        **{
                            field_name: StringSubclass(
                                getattr(task, field_name)
                            )
                        },
                    )
        for hostile_tools in (
            TupleSubclass(task.allowed_tools),
            tuple(StringSubclass(item) for item in task.allowed_tools),
        ):
            with self.assertRaises(DependencyDagExecutionPlanError):
                replace(task, allowed_tools=hostile_tools)
        hostile_node = OperatorNode(
            StringSubclass(task.graph.nodes[0].name),
            task.graph.nodes[0].parameters,
        )
        hostile_graph = NormalizedSemanticGraph(
            (hostile_node, *task.graph.nodes[1:]),
            task.graph.dependencies,
        )
        with self.assertRaises(DependencyDagExecutionPlanError):
            replace(task, graph=hostile_graph)
        hostile_dependencies = NormalizedSemanticGraph(
            task.graph.nodes,
            TupleSubclass(task.graph.dependencies),
        )
        with self.assertRaises(DependencyDagExecutionPlanError):
            replace(task, graph=hostile_dependencies)

        node = DependencyDagNode("a", 0, 0, ())
        with self.assertRaises(DependencyDagExecutionPlanError):
            replace(node, node_id=StringSubclass("a"))
        with self.assertRaises(DependencyDagExecutionPlanError):
            replace(node, prerequisites=TupleSubclass(()))
        graph = DependencyDag((node,))
        with self.assertRaises(DependencyDagExecutionPlanError):
            DependencyDag(TupleSubclass(graph.nodes))

        hostile_source = InputFile(
            StringSubclass(DEPENDENCY_DAG_EXECUTION_PLAN_INPUT),
            _adjacency(),
            0o600,
            100,
        )
        hostile_definition = FixtureDefinition(
            "fixture.hostile-source-path",
            (hostile_source,),
            (),
        )
        with self.assertRaises(DependencyDagExecutionPlanError):
            derive_dependency_dag_execution_plan_state(
                hostile_definition,
                DependencyDagExecutionPlanParameters(
                    "json-adjacency", "utf8-smallest"
                ),
            )
        hostile_expected = ExpectedFile(
            StringSubclass(DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT),
            DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_MAXIMUM_BYTES,
            0o644,
        )
        expected_definition = FixtureDefinition(
            "fixture.hostile-expected-path",
            (
                InputFile(
                    DEPENDENCY_DAG_EXECUTION_PLAN_INPUT,
                    _adjacency(),
                    0o600,
                    100,
                ),
            ),
            (hostile_expected,),
        )
        with self.assertRaises(DependencyDagExecutionPlanError):
            derive_dependency_dag_execution_plan_state(
                expected_definition,
                DependencyDagExecutionPlanParameters(
                    "json-adjacency", "utf8-smallest"
                ),
            )

        bundle = build_dependency_dag_execution_plan_fixture_bundle(
            task, PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        )
        with self.assertRaises(DependencyDagExecutionPlanError):
            replace(bundle.oracle, state=StateProxy(bundle.oracle.state))
        with self.assertRaises(DependencyDagExecutionPlanError):
            replace(
                bundle,
                schema_version=StringSubclass(bundle.schema_version),
            )
        with self.assertRaises(DependencyDagExecutionPlanError):
            replace(bundle, candidate_execution_authorized=True)
        with self.assertRaises(DependencyDagExecutionPlanError):
            replace(bundle, fixture_definition_sha256="0" * 64)
        with self.assertRaises(DependencyDagExecutionPlanError):
            replace(
                bundle,
                descriptor=OpaqueFixtureDescriptor(
                    "fx-" + "0" * 24,
                    "0" * 64,
                    bundle.task_contract_sha256,
                ),
            )
        self.assertFalse(
            verify_dependency_dag_execution_plan_fixture_bundle(object())
        )
        corrupted = copy.copy(bundle)
        object.__delattr__(corrupted, "oracle")
        self.assertFalse(
            verify_dependency_dag_execution_plan_fixture_bundle(corrupted)
        )
        self.assertFalse(
            verify_dependency_dag_execution_plan_fixture_for_task_profile(
                task, PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0], corrupted
            )
        )

    def test_source_mutation_changes_both_oracles(self) -> None:
        task = TASK_BY_CELL[
            ("json-adjacency", "declared-priority")
        ]
        bundle = build_dependency_dag_execution_plan_fixture_bundle(
            task, PROFILE_BY_ID["spaces-unicode"]
        )
        inputs = list(bundle.definition.inputs)
        index = next(
            index
            for index, item in enumerate(inputs)
            if type(item) is InputFile
            and item.path == DEPENDENCY_DAG_EXECUTION_PLAN_INPUT
        )
        source = inputs[index]
        self.assertIs(type(source), InputFile)
        value = json.loads(source.content)
        value["nodes"][0]["priority"] = 999_999
        inputs[index] = replace(source, content=_json_bytes(value))
        mutated = FixtureDefinition(
            bundle.definition.fixture_id,
            tuple(inputs),
            bundle.definition.expected_files,
        )
        primary = derive_dependency_dag_execution_plan_state(
            mutated, task.parameters
        )
        reference = reference_dependency_dag_execution_plan_state(
            mutated, task.parameters
        )
        self.assertEqual(primary, reference)
        self.assertNotEqual(primary, bundle.oracle.state)


class DependencyDagExecutionPlanOutputTests(unittest.TestCase):
    def test_semantic_json_format_and_key_order_are_accepted(self) -> None:
        task = TASK_BY_CELL[
            ("json-adjacency", "largest-fanout")
        ]
        bundle = build_dependency_dag_execution_plan_fixture_bundle(
            task, PROFILE_BY_ID["spaces-unicode"]
        )
        value = json.loads(bundle.oracle.state.content)
        varied = _json_bytes(
            dict(reversed(list(value.items()))),
            canonical=False,
        )
        self.assertEqual(
            parse_dependency_dag_execution_plan_output(varied),
            bundle.oracle.state.content,
        )

    def test_output_rejects_closed_schema_type_order_and_bound_mutations(
        self,
    ) -> None:
        task = TASK_BY_CELL[
            ("json-adjacency", "utf8-smallest")
        ]
        bundle = build_dependency_dag_execution_plan_fixture_bundle(
            task, PROFILE_BY_ID["partial-permissions"]
        )
        valid = json.loads(bundle.oracle.state.content)
        mutations: list[dict[str, object]] = []
        extra = copy.deepcopy(valid)
        extra["extra"] = 1
        mutations.append(extra)
        bool_count = copy.deepcopy(valid)
        bool_count["node_count"] = True
        mutations.append(bool_count)
        nonempty_plan = copy.deepcopy(valid)
        nonempty_plan["plan"] = ["free-root"]
        mutations.append(nonempty_plan)
        reversed_blocked = copy.deepcopy(valid)
        reversed_blocked["blocked_nodes"].reverse()
        mutations.append(reversed_blocked)
        noncyclic_subset = copy.deepcopy(valid)
        noncyclic_subset["cyclic_nodes"] = ["not-blocked"]
        mutations.append(noncyclic_subset)
        duplicate = copy.deepcopy(valid)
        duplicate["blocked_nodes"].append(duplicate["blocked_nodes"][0])
        mutations.append(duplicate)
        for value in mutations:
            with self.subTest(value=str(value)[:100]):
                with self.assertRaises(DependencyDagExecutionPlanError):
                    parse_dependency_dag_execution_plan_output(
                        _json_bytes(value)
                    )
        with self.assertRaises(DependencyDagExecutionPlanError):
            parse_dependency_dag_execution_plan_output(
                b'{"status":"cycle","status":"valid"}\n'
            )
        with self.assertRaises(DependencyDagExecutionPlanError):
            parse_dependency_dag_execution_plan_output(
                b"x"
                * (
                    DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_MAXIMUM_BYTES
                    + 1
                )
            )


class DependencyDagExecutionPlanBoundsTests(unittest.TestCase):
    def test_conservative_output_bound_is_explicit_and_workspace_safe(
        self,
    ) -> None:
        self.assertEqual(
            compute_dependency_dag_execution_plan_proved_output_bound(),
            DEPENDENCY_DAG_EXECUTION_PLAN_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES,
        )
        self.assertEqual(
            DEPENDENCY_DAG_EXECUTION_PLAN_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES,
            DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_MAXIMUM_BYTES,
        )
        self.assertLess(
            DEPENDENCY_DAG_EXECUTION_PLAN_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES,
            MAX_TOTAL_BYTES,
        )


class DependencyDagExecutionPlanWorkspaceTests(unittest.TestCase):
    def test_all_100_task_profile_oracles_pass_workspace_verifier(
        self,
    ) -> None:
        for task in TASKS:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                with self.subTest(
                    encoding=task.parameters.graph_encoding,
                    policy=task.parameters.tie_break_policy,
                    profile=profile.profile_id,
                ), tempfile.TemporaryDirectory() as temporary:
                    bundle = (
                        build_dependency_dag_execution_plan_fixture_bundle(
                            task, profile
                        )
                    )
                    with materialize_dependency_dag_execution_plan_fixture(
                        task,
                        profile,
                        bundle,
                        Path(temporary) / "workspace",
                    ) as handle:
                        _write_state(handle, bundle.oracle.state.content)
                        self.assertTrue(
                            verify_dependency_dag_execution_plan_workspace(
                                task, profile, bundle, handle
                            )
                        )

    def test_workspace_accepts_semantic_formatting(self) -> None:
        task = TASK_BY_CELL[
            ("json-edge-list", "shortest-depth")
        ]
        profile = PROFILE_BY_ID["spaces-unicode"]
        bundle = build_dependency_dag_execution_plan_fixture_bundle(
            task, profile
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_dependency_dag_execution_plan_fixture(
                task,
                profile,
                bundle,
                Path(temporary) / "workspace",
            ) as handle:
                value = json.loads(bundle.oracle.state.content)
                _write_state(
                    handle,
                    _json_bytes(
                        dict(reversed(list(value.items()))),
                        canonical=False,
                    ),
                )
                self.assertTrue(
                    verify_dependency_dag_execution_plan_workspace(
                        task, profile, bundle, handle
                    )
                )

    def test_workspace_rejects_tree_semantic_mode_and_input_mutations(
        self,
    ) -> None:
        task = TASK_BY_CELL[("csv-edges", "largest-fanout")]
        profile = PROFILE_BY_ID["symlinks-ordering"]
        bundle = build_dependency_dag_execution_plan_fixture_bundle(
            task, profile
        )
        mutations = ("semantic", "mode", "extra", "input-mode", "hardlink")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                with materialize_dependency_dag_execution_plan_fixture(
                    task,
                    profile,
                    bundle,
                    Path(temporary) / "workspace",
                ) as handle:
                    _write_state(handle, bundle.oracle.state.content)
                    output = (
                        handle.workspace
                        / DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT
                    )
                    if mutation == "semantic":
                        value = json.loads(output.read_bytes())
                        value["edge_count"] += 1
                        output.write_bytes(_json_bytes(value))
                    elif mutation == "mode":
                        output.chmod(0o600)
                    elif mutation == "extra":
                        (handle.workspace / "output/extra").write_bytes(
                            b"unexpected"
                        )
                    elif mutation == "input-mode":
                        (
                            handle.workspace
                            / DEPENDENCY_DAG_EXECUTION_PLAN_INPUT
                        ).chmod(0o644)
                    elif mutation == "hardlink":
                        os.link(output, handle.workspace / "alias")
                    self.assertFalse(
                        verify_dependency_dag_execution_plan_workspace(
                            task, profile, bundle, handle
                        )
                    )

    def test_workspace_rejects_symlink_target_mutation(self) -> None:
        task = TASK_BY_CELL[
            ("line-oriented-dependencies", "stable-input-order")
        ]
        profile = PROFILE_BY_ID["symlinks-ordering"]
        bundle = build_dependency_dag_execution_plan_fixture_bundle(
            task, profile
        )
        self.assertTrue(
            any(
                type(item) is InputSymlink
                for item in bundle.definition.inputs
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_dependency_dag_execution_plan_fixture(
                task, profile, bundle, Path(temporary) / "workspace"
            ) as handle:
                _write_state(handle, bundle.oracle.state.content)
                link = handle.workspace / "input/distractors/link"
                link.unlink()
                os.symlink("changed-target", link)
                self.assertFalse(
                    verify_dependency_dag_execution_plan_workspace(
                        task, profile, bundle, handle
                    )
                )


if __name__ == "__main__":
    unittest.main()
