from __future__ import annotations

import ast
import copy
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_jsonl_csv_enrichment_compose import (
    JSONL_CSV_ENRICHMENT_COMPOSE_ALLOWED_TOOLS,
    JSONL_CSV_ENRICHMENT_COMPOSE_ATOMICITY_OBSERVED,
    JSONL_CSV_ENRICHMENT_COMPOSE_CANDIDATE_EXIT_STATUS_OBSERVED,
    JSONL_CSV_ENRICHMENT_COMPOSE_FAMILY_ID,
    JSONL_CSV_ENRICHMENT_COMPOSE_FIELD_MAXIMUM_UTF8_BYTES,
    JSONL_CSV_ENRICHMENT_COMPOSE_FINAL_OUTPUT_OBSERVED,
    JSONL_CSV_ENRICHMENT_COMPOSE_INPUT_PRESERVATION_OBSERVED,
    JSONL_CSV_ENRICHMENT_COMPOSE_INTERMEDIATE_MATERIALIZATION_OBSERVED,
    JSONL_CSV_ENRICHMENT_COMPOSE_JOIN_LAYOUTS,
    JSONL_CSV_ENRICHMENT_COMPOSE_LEFT_INPUT,
    JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_ENRICHED_ROWS,
    JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_PHYSICAL_RECORDS,
    JSONL_CSV_ENRICHMENT_COMPOSE_MISSING_FIELD_POLICIES,
    JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT,
    JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_MAXIMUM_BYTES,
    JSONL_CSV_ENRICHMENT_COMPOSE_PROVED_MAXIMUM_CANONICAL_OUTPUT_BYTES,
    JSONL_CSV_ENRICHMENT_COMPOSE_READ_SCOPE_OBSERVED,
    JSONL_CSV_ENRICHMENT_COMPOSE_RIGHT_INPUT,
    JSONL_CSV_ENRICHMENT_COMPOSE_TOOL_HISTORY_OBSERVED,
    JSONL_CSV_ENRICHMENT_COMPOSE_TRANSIENT_STATE_OBSERVED,
    JSONL_CSV_ENRICHMENT_COMPOSE_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
    JSONL_CSV_ENRICHMENT_COMPOSE_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE,
    JsonlCsvEnrichmentComposeError,
    JsonlCsvEnrichmentComposeParameters,
    build_jsonl_csv_enrichment_compose_fixture_bundle,
    build_jsonl_csv_enrichment_compose_tasks,
    compute_jsonl_csv_enrichment_compose_discrimination_sha256,
    compute_jsonl_csv_enrichment_compose_proved_output_bound,
    derive_jsonl_csv_enrichment_compose_state,
    jsonl_csv_enrichment_compose_task_semantic_core,
    materialize_jsonl_csv_enrichment_compose_fixture,
    parse_jsonl_csv_enrichment_compose_output,
    parse_jsonl_csv_enrichment_source,
    reference_jsonl_csv_enrichment_compose_state,
    validate_jsonl_csv_enrichment_compose_fixture_bundle,
    validate_jsonl_csv_enrichment_compose_fixture_for_task_profile,
    verify_jsonl_csv_enrichment_compose_fixture_bundle,
    verify_jsonl_csv_enrichment_compose_fixture_for_task_profile,
    verify_jsonl_csv_enrichment_compose_workspace,
)
from cbds.executable_static_types import OpaqueFixtureDescriptor
from cbds.executable_workspace import FixtureDefinition, InputFile
from cbds.executable_workspace import InputSymlink


TASKS = build_jsonl_csv_enrichment_compose_tasks()
TASK_BY_CELL = {
    (task.parameters.join_layout, task.parameters.missing_field_policy): task
    for task in TASKS
}
PROFILE_BY_ID = {
    profile.profile_id: profile
    for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
}
EXPECTED_DISCRIMINATION_SHA256 = (
    "732c1438a4337d2043ee85e2eb4e9e7c437a0051eb1a828cdac6139845db0e94"
)


def _objects(payload: bytes) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in payload.decode("utf-8").splitlines()
    ]


def _render(values: list[dict[str, object]]) -> bytes:
    return b"".join(
        (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        for value in values
    )


def _write_output(handle: object, payload: bytes, mode: int = 0o644) -> Path:
    path = handle.workspace / JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o755)
    path.write_bytes(payload)
    path.chmod(mode)
    return path


def _example_definition(
    left: bytes | None = None,
    right: bytes | None = None,
) -> FixtureDefinition:
    return FixtureDefinition(
        "fixture.compose.policy-example",
        (
            InputFile(
                JSONL_CSV_ENRICHMENT_COMPOSE_LEFT_INPUT,
                left
                if left is not None
                else (
                    b'{"id":"a","left":"A"}\n'
                    b'{"left":"B"}\n'
                    b'{"id":"c","left":"C"}\n'
                ),
                0o600,
                100,
            ),
            InputFile(
                JSONL_CSV_ENRICHMENT_COMPOSE_RIGHT_INPUT,
                right
                if right is not None
                else b"id,right\r\na,X\r\nb,\r\n",
                0o600,
                101,
            ),
        ),
        (),
    )


class JsonlCsvComposeTaskTests(unittest.TestCase):
    def test_grid_is_exact_unique_public_and_discriminable(self) -> None:
        expected = tuple(
            (layout, policy)
            for layout in JSONL_CSV_ENRICHMENT_COMPOSE_JOIN_LAYOUTS
            for policy in JSONL_CSV_ENRICHMENT_COMPOSE_MISSING_FIELD_POLICIES
        )
        self.assertEqual(len(TASKS), 20)
        self.assertEqual(
            tuple(
                (
                    task.parameters.join_layout,
                    task.parameters.missing_field_policy,
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
            compute_jsonl_csv_enrichment_compose_discrimination_sha256(
                TASKS
            ),
            EXPECTED_DISCRIMINATION_SHA256,
        )
        for task in TASKS:
            with self.subTest(task=task.task_id):
                task.__post_init__()
                self.assertEqual(
                    task.family_id,
                    JSONL_CSV_ENRICHMENT_COMPOSE_FAMILY_ID,
                )
                self.assertEqual(
                    task.allowed_tools,
                    JSONL_CSV_ENRICHMENT_COMPOSE_ALLOWED_TOOLS,
                )
                self.assertEqual(len(task.fixtures), 5)
                self.assertTrue(task.public)
                self.assertFalse(task.sealed)
                self.assertFalse(task.candidate_execution_authorized)
                self.assertFalse(task.model_selection_eligible)
                self.assertFalse(task.claim_authorized)
                semantic = jsonl_csv_enrichment_compose_task_semantic_core(
                    task.parameters, task.prompt, task.graph
                )
                self.assertEqual(
                    semantic["family_id"],
                    JSONL_CSV_ENRICHMENT_COMPOSE_FAMILY_ID,
                )
                self.assertIn(
                    "missing id filled with empty string or null remains "
                    "nonjoinable",
                    task.prompt,
                )

    def test_axis_label_free_behavioral_signatures_are_all_unique(self) -> None:
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        signatures: set[tuple[str, str, str]] = set()
        for task in TASKS:
            bundle = build_jsonl_csv_enrichment_compose_fixture_bundle(
                task, profile
            )
            sources = {
                item.path: item.content
                for item in bundle.definition.inputs
                if type(item) is InputFile
                and item.path
                in {
                    JSONL_CSV_ENRICHMENT_COMPOSE_LEFT_INPUT,
                    JSONL_CSV_ENRICHMENT_COMPOSE_RIGHT_INPUT,
                }
            }
            body = {
                "enriched": [
                    row.to_json_record()
                    for row in bundle.oracle.state.enriched
                ],
                "rejects": [
                    row.to_json_record()
                    for row in bundle.oracle.state.rejects
                ],
                "source_rejects": [
                    row.to_json_record()
                    for row in bundle.oracle.state.source_rejects
                ],
            }
            body_bytes = json.dumps(
                body,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            signatures.add(
                (
                    sha256(
                        sources[
                            JSONL_CSV_ENRICHMENT_COMPOSE_LEFT_INPUT
                        ]
                    ).hexdigest(),
                    sha256(
                        sources[
                            JSONL_CSV_ENRICHMENT_COMPOSE_RIGHT_INPUT
                        ]
                    ).hexdigest(),
                    sha256(body_bytes).hexdigest(),
                )
            )
        self.assertEqual(len(signatures), 20)

    def test_parameter_task_graph_and_authority_mutations_fail(self) -> None:
        task = TASKS[0]
        with self.assertRaises(JsonlCsvEnrichmentComposeError):
            JsonlCsvEnrichmentComposeParameters(  # type: ignore[arg-type]
                "invented", "drop-row"
            )
        with self.assertRaises(JsonlCsvEnrichmentComposeError):
            JsonlCsvEnrichmentComposeParameters(  # type: ignore[arg-type]
                "jsonl-left-csv-right", "invented"
            )
        with self.assertRaises(JsonlCsvEnrichmentComposeError):
            replace(task, prompt=task.prompt + " ")
        with self.assertRaises(JsonlCsvEnrichmentComposeError):
            replace(task, candidate_execution_authorized=True)
        with self.assertRaises(JsonlCsvEnrichmentComposeError):
            replace(task, allowed_tools=task.allowed_tools + ("cat",))
        with self.assertRaises(JsonlCsvEnrichmentComposeError):
            replace(task, fixtures=(task.fixtures[0],) * 5)

    def test_observation_boundary_is_explicit(self) -> None:
        self.assertTrue(JSONL_CSV_ENRICHMENT_COMPOSE_FINAL_OUTPUT_OBSERVED)
        self.assertTrue(
            JSONL_CSV_ENRICHMENT_COMPOSE_INPUT_PRESERVATION_OBSERVED
        )
        self.assertTrue(
            JSONL_CSV_ENRICHMENT_COMPOSE_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE
        )
        for value in (
            JSONL_CSV_ENRICHMENT_COMPOSE_INTERMEDIATE_MATERIALIZATION_OBSERVED,
            JSONL_CSV_ENRICHMENT_COMPOSE_ATOMICITY_OBSERVED,
            JSONL_CSV_ENRICHMENT_COMPOSE_TOOL_HISTORY_OBSERVED,
            JSONL_CSV_ENRICHMENT_COMPOSE_READ_SCOPE_OBSERVED,
            JSONL_CSV_ENRICHMENT_COMPOSE_CANDIDATE_EXIT_STATUS_OBSERVED,
            JSONL_CSV_ENRICHMENT_COMPOSE_TRANSIENT_STATE_OBSERVED,
            JSONL_CSV_ENRICHMENT_COMPOSE_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
        ):
            self.assertFalse(value)

    def test_production_module_contains_no_assert_statement(self) -> None:
        source_path = (
            ROOT
            / "src"
            / "cbds"
            / "executable_jsonl_csv_enrichment_compose.py"
        )
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        self.assertFalse(
            any(isinstance(node, ast.Assert) for node in ast.walk(tree))
        )


class JsonlCsvComposeFixtureTests(unittest.TestCase):
    def test_all_100_bundles_reconstruct_with_independent_oracles(self) -> None:
        fixture_ids: set[str] = set()
        policy_shapes: set[tuple[str, int, int, int]] = set()
        count = 0
        for task in TASKS:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                with self.subTest(
                    layout=task.parameters.join_layout,
                    policy=task.parameters.missing_field_policy,
                    profile=profile.profile_id,
                ):
                    bundle = build_jsonl_csv_enrichment_compose_fixture_bundle(
                        task, profile
                    )
                    validate_jsonl_csv_enrichment_compose_fixture_bundle(
                        bundle
                    )
                    validate_jsonl_csv_enrichment_compose_fixture_for_task_profile(
                        task, profile, bundle
                    )
                    self.assertTrue(
                        verify_jsonl_csv_enrichment_compose_fixture_bundle(
                            bundle
                        )
                    )
                    self.assertTrue(
                        verify_jsonl_csv_enrichment_compose_fixture_for_task_profile(
                            task, profile, bundle
                        )
                    )
                    primary = derive_jsonl_csv_enrichment_compose_state(
                        bundle.definition, task.parameters
                    )
                    reference = (
                        reference_jsonl_csv_enrichment_compose_state(
                            bundle.definition, task.parameters
                        )
                    )
                    self.assertEqual(primary, reference)
                    self.assertEqual(primary, bundle.oracle.state)
                    self.assertEqual(
                        parse_jsonl_csv_enrichment_compose_output(
                            primary.output
                        ),
                        primary.output,
                    )
                    fixture_ids.add(bundle.descriptor.fixture_sha256)
                    policy_shapes.add(
                        (
                            task.parameters.missing_field_policy,
                            len(primary.enriched),
                            len(primary.rejects),
                            len(primary.source_rejects),
                        )
                    )
                    count += 1
        self.assertEqual(count, 100)
        self.assertEqual(len(fixture_ids), 100)
        self.assertEqual(
            {shape[0] for shape in policy_shapes},
            set(JSONL_CSV_ENRICHMENT_COMPOSE_MISSING_FIELD_POLICIES),
        )

    def test_policy_table_and_missing_id_nonjoinability_are_exact(self) -> None:
        definition = _example_definition()
        states = {
            policy: derive_jsonl_csv_enrichment_compose_state(
                definition,
                JsonlCsvEnrichmentComposeParameters(
                    "jsonl-left-csv-right", policy
                ),
            )
            for policy in JSONL_CSV_ENRICHMENT_COMPOSE_MISSING_FIELD_POLICIES
        }
        for policy, primary in states.items():
            reference = reference_jsonl_csv_enrichment_compose_state(
                definition,
                JsonlCsvEnrichmentComposeParameters(
                    "jsonl-left-csv-right", policy
                ),
            )
            self.assertEqual(primary, reference)

        self.assertEqual(
            [
                (row.identifier, row.left, row.right, row.matched)
                for row in states["drop-row"].enriched
            ],
            [("a", "A", "X", True)],
        )
        self.assertEqual(
            [
                (row.identifier, row.left, row.right, row.matched)
                for row in states["empty-string"].enriched
            ],
            [
                ("", "B", "", False),
                ("a", "A", "X", True),
                ("c", "C", "", False),
            ],
        )
        self.assertEqual(
            [
                (row.identifier, row.left, row.right, row.matched)
                for row in states["null-value"].enriched
            ],
            [
                (None, "B", None, False),
                ("a", "A", "X", True),
                ("c", "C", None, False),
            ],
        )
        self.assertEqual(
            [
                (
                    row.source,
                    row.source_index,
                    row.identifier,
                    row.missing_fields,
                )
                for row in states["emit-reject-row"].rejects
            ],
            [
                (JSONL_CSV_ENRICHMENT_COMPOSE_LEFT_INPUT, 1, None, ("id",)),
                (JSONL_CSV_ENRICHMENT_COMPOSE_RIGHT_INPUT, 1, "b", ("right",)),
                ("join", 2, "c", ("right",)),
            ],
        )
        rejected = states["reject-source-file"]
        self.assertFalse(rejected.enriched)
        self.assertEqual(
            [
                (
                    row.source,
                    row.affected_count,
                    row.missing_fields,
                )
                for row in rejected.source_rejects
            ],
            [
                (
                    JSONL_CSV_ENRICHMENT_COMPOSE_LEFT_INPUT,
                    1,
                    ("id",),
                ),
                (
                    JSONL_CSV_ENRICHMENT_COMPOSE_RIGHT_INPUT,
                    2,
                    ("right",),
                ),
            ],
        )

    def test_duplicate_sources_retain_full_cartesian_multiplicity(self) -> None:
        bundle = build_jsonl_csv_enrichment_compose_fixture_bundle(
            TASK_BY_CELL[("jsonl-both-with-csv-output", "drop-row")],
            PROFILE_BY_ID["empty-duplicates"],
        )
        rows = [
            row
            for row in bundle.oracle.state.enriched
            if row.identifier == "duplicate"
        ]
        self.assertEqual(len(rows), 4)
        self.assertEqual(
            {
                (row.left, row.right, row.matched)
                for row in rows
            },
            {("same", "same right", True)},
        )

    def test_bundle_binding_and_authority_mutations_fail_closed(self) -> None:
        task = TASKS[0]
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        bundle = build_jsonl_csv_enrichment_compose_fixture_bundle(
            task, profile
        )
        with self.assertRaises(JsonlCsvEnrichmentComposeError):
            replace(bundle, candidate_execution_authorized=True)
        with self.assertRaises(JsonlCsvEnrichmentComposeError):
            replace(bundle, fixture_definition_sha256="0" * 64)
        with self.assertRaises(JsonlCsvEnrichmentComposeError):
            replace(
                bundle,
                descriptor=OpaqueFixtureDescriptor(
                    "fx-" + "0" * 24,
                    "0" * 64,
                    bundle.task_contract_sha256,
                ),
            )
        self.assertFalse(
            verify_jsonl_csv_enrichment_compose_fixture_bundle(object())
        )
        corrupted = copy.copy(bundle)
        object.__delattr__(corrupted, "oracle")
        self.assertFalse(
            verify_jsonl_csv_enrichment_compose_fixture_bundle(corrupted)
        )
        self.assertFalse(
            verify_jsonl_csv_enrichment_compose_fixture_for_task_profile(
                task, profile, corrupted
            )
        )


class JsonlCsvComposeSourceParserTests(unittest.TestCase):
    def test_valid_jsonl_and_csv_quoting_and_missing_fields(self) -> None:
        jsonl = (
            b'{"id":"a","left":"comma, quote \\" ok"}\n'
            b'{"left":"missing id"}\n'
            b'{"id":"missing-left"}\n'
        )
        rows = parse_jsonl_csv_enrichment_source(
            jsonl, "jsonl", "left"
        )
        self.assertEqual(
            [
                (row.identifier, row.value, row.missing_fields)
                for row in rows
            ],
            [
                ("a", 'comma, quote " ok', ()),
                (None, "missing id", ("id",)),
                ("missing-left", None, ("left",)),
            ],
        )
        csv_payload = (
            b'id,right\r\n'
            b'a,"comma, doubled "" quote"\r\n'
            b',"missing id"\r\n'
            b'missing-right,\r\n'
        )
        rows = parse_jsonl_csv_enrichment_source(
            csv_payload, "csv", "right"
        )
        self.assertEqual(
            [
                (row.identifier, row.value, row.missing_fields)
                for row in rows
            ],
            [
                ("a", 'comma, doubled " quote', ()),
                (None, "missing id", ("id",)),
                ("missing-right", None, ("right",)),
            ],
        )

    def test_jsonl_fail_closed_on_types_keys_duplicates_and_framing(self) -> None:
        invalid = (
            b'{"id":"a","left":"x"}',
            b'{"id":"a","left":"x"}\r\n',
            b'\n',
            b'{}\n',
            b'{"id":"a","extra":"x"}\n',
            b'{"id":"a","id":"b"}\n',
            b'{"id":1,"left":"x"}\n',
            b'{"id":null,"left":"x"}\n',
            b'{"id":"a","left":null}\n',
            b'{"id":"","left":"x"}\n',
            b'["a","x"]\n',
            b'{"id":"a\\n","left":"x"}\n',
            b"\xff\n",
            (
                b'{"id":"'
                + b"x"
                * (JSONL_CSV_ENRICHMENT_COMPOSE_FIELD_MAXIMUM_UTF8_BYTES + 1)
                + b'"}\n'
            ),
            b"[" * 20_000 + b"0" + b"]" * 20_000 + b"\n",
        )
        for payload in invalid:
            with self.subTest(payload=payload[:60]):
                with self.assertRaises(JsonlCsvEnrichmentComposeError):
                    parse_jsonl_csv_enrichment_source(
                        payload, "jsonl", "left"
                    )

    def test_csv_fail_closed_on_header_width_quotes_newlines_and_bound(self) -> None:
        invalid = (
            b"id,left\na,x\n",
            b"id,left\r\na,x",
            b"left,id\r\nx,a\r\n",
            b"id,left\r\n",
            b"id,left\r\na\r\n",
            b"id,left\r\na,x,extra\r\n",
            b'id,left\r\n"unterminated,x\r\n',
            b'id,left\r\n"a"x,y\r\n',
            b"id,left\r\n\xff,x\r\n",
            b"\xef\xbb\xbfid,left\r\na,x\r\n",
            (
                b"id,left\r\n"
                + b"x"
                * (JSONL_CSV_ENRICHMENT_COMPOSE_FIELD_MAXIMUM_UTF8_BYTES + 1)
                + b",x\r\n"
            ),
        )
        for payload in invalid:
            with self.subTest(payload=payload[:60]):
                with self.assertRaises(JsonlCsvEnrichmentComposeError):
                    parse_jsonl_csv_enrichment_source(
                        payload, "csv", "left"
                    )

        accepted = b"id,left\r\n" + b"a,x\r\n" * 127
        rejected = b"id,left\r\n" + b"a,x\r\n" * 128
        self.assertEqual(
            len(
                parse_jsonl_csv_enrichment_source(
                    accepted, "csv", "left"
                )
            ),
            127,
        )
        with self.assertRaises(JsonlCsvEnrichmentComposeError):
            parse_jsonl_csv_enrichment_source(
                rejected, "csv", "left"
            )

    def test_exact_type_and_unknown_codec_side_fail(self) -> None:
        for encoding, side in (
            ("unknown", "left"),
            ("jsonl", "unknown"),
        ):
            with self.subTest(encoding=encoding, side=side):
                with self.assertRaises(JsonlCsvEnrichmentComposeError):
                    parse_jsonl_csv_enrichment_source(
                        b'{"id":"a"}\n',
                        encoding,  # type: ignore[arg-type]
                        side,  # type: ignore[arg-type]
                    )
        with self.assertRaises(JsonlCsvEnrichmentComposeError):
            parse_jsonl_csv_enrichment_source(
                bytearray(b'{"id":"a"}\n'),  # type: ignore[arg-type]
                "jsonl",
                "left",
            )

    def test_jsonl_physical_record_and_source_byte_boundaries(self) -> None:
        row = b'{"id":"a","left":"x"}\n'
        accepted = row * 128
        rejected = row * 129
        self.assertEqual(
            len(
                parse_jsonl_csv_enrichment_source(
                    accepted, "jsonl", "left"
                )
            ),
            128,
        )
        with self.assertRaises(JsonlCsvEnrichmentComposeError):
            parse_jsonl_csv_enrichment_source(
                rejected, "jsonl", "left"
            )
        with self.assertRaises(JsonlCsvEnrichmentComposeError):
            parse_jsonl_csv_enrichment_source(
                b"x" * (64 * 1024 + 1), "jsonl", "left"
            )


class JsonlCsvComposeOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bundle = build_jsonl_csv_enrichment_compose_fixture_bundle(
            TASK_BY_CELL[
                ("jsonl-both-with-csv-output", "emit-reject-row")
            ],
            PROFILE_BY_ID["spaces-unicode"],
        )
        self.output = self.bundle.oracle.state.output

    def test_key_order_and_insignificant_whitespace_are_semantic(self) -> None:
        values = _objects(self.output)
        varied = b"".join(
            (
                json.dumps(
                    dict(reversed(list(value.items()))),
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(", ", ": "),
                )
                + "\n"
            ).encode("utf-8")
            for value in values
        )
        self.assertNotEqual(varied, self.output)
        self.assertEqual(
            parse_jsonl_csv_enrichment_compose_output(varied),
            self.output,
        )

    def test_schema_type_count_order_policy_and_framing_mutants_fail(self) -> None:
        base = _objects(self.output)
        mutants: list[bytes] = [
            self.output[:-1],
            self.output.replace(b"\n", b"\r\n", 1),
            b"\n" + self.output,
            self.output + b"\n",
            b"\xff\n",
            b"[" * 100_000 + b"0" + b"]" * 100_000 + b"\n",
        ]
        changed = [dict(value) for value in base]
        changed[0]["extra"] = 1
        mutants.append(_render(changed))
        changed = [dict(value) for value in base]
        changed[0]["enriched_count"] = (
            int(changed[0]["enriched_count"]) + 1
        )
        mutants.append(_render(changed))
        changed = [dict(value) for value in base]
        changed[0]["reject_count"] = True
        mutants.append(_render(changed))
        changed = [dict(value) for value in base]
        enriched_index = next(
            index
            for index, value in enumerate(changed)
            if value.get("record") == "enriched"
        )
        changed[enriched_index]["matched"] = 1
        mutants.append(_render(changed))
        changed = [dict(value) for value in base]
        reject_index = next(
            index
            for index, value in enumerate(changed)
            if value.get("record") == "reject"
        )
        changed[reject_index]["source_index"] = True
        mutants.append(_render(changed))
        changed = [dict(value) for value in base]
        changed[reject_index]["missing_fields"] = ["right", "id"]
        mutants.append(_render(changed))
        changed = [dict(value) for value in base]
        changed[enriched_index], changed[reject_index] = (
            changed[reject_index],
            changed[enriched_index],
        )
        mutants.append(_render(changed))
        duplicate = (
            self.output.splitlines()[0].replace(
                b'"record":"compose"',
                b'"record":"compose","record":"compose"',
            )
            + b"\n"
            + b"\n".join(self.output.splitlines()[1:])
            + b"\n"
        )
        mutants.append(duplicate)
        for mutant in mutants:
            with self.subTest(mutant=mutant[:100]):
                with self.assertRaises(JsonlCsvEnrichmentComposeError):
                    parse_jsonl_csv_enrichment_compose_output(mutant)

    def test_output_bound_and_deep_or_large_numeric_json_fail(self) -> None:
        with self.assertRaises(JsonlCsvEnrichmentComposeError):
            parse_jsonl_csv_enrichment_compose_output(
                b"x"
                * (JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_MAXIMUM_BYTES + 1)
            )
        huge = (
            b'{"record":"compose","join_layout":"jsonl-left-csv-right",'
            b'"missing_field_policy":"drop-row","enriched_count":'
            + b"1" * 10_000
            + b',"reject_count":0,"source_reject_count":0}\n'
        )
        with self.assertRaises(JsonlCsvEnrichmentComposeError):
            parse_jsonl_csv_enrichment_compose_output(huge)


class JsonlCsvComposeBoundsAndMutationTests(unittest.TestCase):
    def test_output_bound_proof_reconstructs_worst_rows_independently(self) -> None:
        worst = "\\" * JSONL_CSV_ENRICHMENT_COMPOSE_FIELD_MAXIMUM_UTF8_BYTES
        header = {
            "record": "compose",
            "join_layout": "jsonl-both-with-csv-output",
            "missing_field_policy": "reject-source-file",
            "enriched_count": JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_ENRICHED_ROWS,
            "reject_count": (
                2
                * JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_PHYSICAL_RECORDS
            ),
            "source_reject_count": 2,
        }
        enriched = {
            "record": "enriched",
            "id": worst,
            "left": worst,
            "right": worst,
            "matched": False,
        }
        reject = {
            "record": "reject",
            "source": JSONL_CSV_ENRICHMENT_COMPOSE_RIGHT_INPUT,
            "source_index": 127,
            "id": worst,
            "missing_fields": ["id", "right"],
        }
        source_reject = {
            "record": "source-reject",
            "source": JSONL_CSV_ENRICHMENT_COMPOSE_RIGHT_INPUT,
            "reason": "required-field-missing",
            "affected_count": 1152,
            "missing_fields": ["id", "right"],
        }

        def size(value: dict[str, object]) -> int:
            return len(
                (
                    json.dumps(
                        value,
                        ensure_ascii=False,
                        allow_nan=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8")
            )

        reconstructed = (
            size(header)
            + JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_ENRICHED_ROWS
            * size(enriched)
            + 2
            * JSONL_CSV_ENRICHMENT_COMPOSE_MAXIMUM_PHYSICAL_RECORDS
            * size(reject)
            + 2 * size(source_reject)
        )
        self.assertEqual(reconstructed, 948_427)
        self.assertEqual(
            reconstructed,
            JSONL_CSV_ENRICHMENT_COMPOSE_PROVED_MAXIMUM_CANONICAL_OUTPUT_BYTES,
        )
        self.assertEqual(
            compute_jsonl_csv_enrichment_compose_proved_output_bound(),
            reconstructed,
        )
        self.assertLessEqual(
            reconstructed,
            JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT_MAXIMUM_BYTES,
        )

    def test_cartesian_expansion_above_1024_fails_in_both_engines(self) -> None:
        left = b"".join(
            b'{"id":"same","left":"x"}\n' for _ in range(33)
        )
        right = b"id,right\r\n" + b"same,y\r\n" * 32
        definition = _example_definition(left, right)
        parameters = JsonlCsvEnrichmentComposeParameters(
            "jsonl-left-csv-right", "drop-row"
        )
        with self.assertRaises(JsonlCsvEnrichmentComposeError):
            derive_jsonl_csv_enrichment_compose_state(
                definition, parameters
            )
        with self.assertRaises(JsonlCsvEnrichmentComposeError):
            reference_jsonl_csv_enrichment_compose_state(
                definition, parameters
            )

    def test_source_byte_and_schema_mutations_change_or_fail_both_oracles(
        self,
    ) -> None:
        task = TASK_BY_CELL[
            ("jsonl-left-csv-right", "empty-string")
        ]
        bundle = build_jsonl_csv_enrichment_compose_fixture_bundle(
            task, PROFILE_BY_ID["spaces-unicode"]
        )
        inputs = list(bundle.definition.inputs)
        index = next(
            index
            for index, item in enumerate(inputs)
            if type(item) is InputFile
            and item.path == JSONL_CSV_ENRICHMENT_COMPOSE_LEFT_INPUT
        )
        source = inputs[index]
        if type(source) is not InputFile:
            self.fail("selected source is not exact InputFile")
        inputs[index] = replace(
            source,
            content=source.content.replace(
                "snow 雪 value".encode("utf-8"),
                "changed value".encode("utf-8"),
            ),
        )
        mutated = FixtureDefinition(
            bundle.definition.fixture_id,
            tuple(inputs),
            bundle.definition.expected_files,
        )
        primary = derive_jsonl_csv_enrichment_compose_state(
            mutated, task.parameters
        )
        reference = reference_jsonl_csv_enrichment_compose_state(
            mutated, task.parameters
        )
        self.assertEqual(primary, reference)
        self.assertNotEqual(primary, bundle.oracle.state)

        inputs[index] = replace(source, content=source.content[:-1])
        malformed = FixtureDefinition(
            bundle.definition.fixture_id,
            tuple(inputs),
            bundle.definition.expected_files,
        )
        with self.assertRaises(JsonlCsvEnrichmentComposeError):
            derive_jsonl_csv_enrichment_compose_state(
                malformed, task.parameters
            )
        with self.assertRaises(JsonlCsvEnrichmentComposeError):
            reference_jsonl_csv_enrichment_compose_state(
                malformed, task.parameters
            )


class JsonlCsvComposeWorkspaceTests(unittest.TestCase):
    def test_all_100_task_profile_oracles_pass_complete_workspace_verifier(
        self,
    ) -> None:
        for task in TASKS:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                with self.subTest(
                    layout=task.parameters.join_layout,
                    policy=task.parameters.missing_field_policy,
                    profile=profile.profile_id,
                ), tempfile.TemporaryDirectory() as temporary:
                    bundle = (
                        build_jsonl_csv_enrichment_compose_fixture_bundle(
                            task, profile
                        )
                    )
                    with materialize_jsonl_csv_enrichment_compose_fixture(
                        task,
                        profile,
                        bundle,
                        Path(temporary) / "workspace",
                    ) as handle:
                        _write_output(
                            handle, bundle.oracle.state.output
                        )
                        self.assertTrue(
                            verify_jsonl_csv_enrichment_compose_workspace(
                                task, profile, bundle, handle
                            )
                        )

    def test_workspace_accepts_semantic_json_and_rejects_mutations(self) -> None:
        task = TASK_BY_CELL[
            ("jsonl-both-with-csv-output", "emit-reject-row")
        ]
        profile = PROFILE_BY_ID["spaces-unicode"]
        bundle = build_jsonl_csv_enrichment_compose_fixture_bundle(
            task, profile
        )
        values = _objects(bundle.oracle.state.output)
        varied = b"".join(
            (
                json.dumps(
                    dict(reversed(list(value.items()))),
                    ensure_ascii=False,
                    separators=(", ", ": "),
                )
                + "\n"
            ).encode("utf-8")
            for value in values
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_jsonl_csv_enrichment_compose_fixture(
                task,
                profile,
                bundle,
                Path(temporary) / "workspace",
            ) as handle:
                output = _write_output(handle, varied)
                self.assertTrue(
                    verify_jsonl_csv_enrichment_compose_workspace(
                        task, profile, bundle, handle
                    )
                )
                output.chmod(0o600)
                self.assertFalse(
                    verify_jsonl_csv_enrichment_compose_workspace(
                        task, profile, bundle, handle
                    )
                )

        with tempfile.TemporaryDirectory() as temporary:
            with materialize_jsonl_csv_enrichment_compose_fixture(
                task,
                profile,
                bundle,
                Path(temporary) / "workspace",
            ) as handle:
                _write_output(handle, bundle.oracle.state.output)
                extra = handle.workspace / "extra"
                extra.write_bytes(b"unexpected")
                self.assertFalse(
                    verify_jsonl_csv_enrichment_compose_workspace(
                        task, profile, bundle, handle
                    )
                )

        with tempfile.TemporaryDirectory() as temporary:
            with materialize_jsonl_csv_enrichment_compose_fixture(
                task,
                profile,
                bundle,
                Path(temporary) / "workspace",
            ) as handle:
                _write_output(handle, bundle.oracle.state.output)
                source = (
                    handle.workspace
                    / JSONL_CSV_ENRICHMENT_COMPOSE_LEFT_INPUT
                )
                source.chmod(0o644)
                self.assertFalse(
                    verify_jsonl_csv_enrichment_compose_workspace(
                        task, profile, bundle, handle
                    )
                )

    def test_workspace_wrong_bytes_and_hardlink_output_fail(self) -> None:
        task = TASK_BY_CELL[
            ("csv-both-with-jsonl-output", "empty-string")
        ]
        profile = PROFILE_BY_ID["leading-dashes-globs"]
        bundle = build_jsonl_csv_enrichment_compose_fixture_bundle(
            task, profile
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_jsonl_csv_enrichment_compose_fixture(
                task,
                profile,
                bundle,
                Path(temporary) / "workspace",
            ) as handle:
                values = _objects(bundle.oracle.state.output)
                values[0]["enriched_count"] = (
                    int(values[0]["enriched_count"]) + 1
                )
                _write_output(handle, _render(values))
                self.assertFalse(
                    verify_jsonl_csv_enrichment_compose_workspace(
                        task, profile, bundle, handle
                    )
                )

        with tempfile.TemporaryDirectory() as temporary:
            with materialize_jsonl_csv_enrichment_compose_fixture(
                task,
                profile,
                bundle,
                Path(temporary) / "workspace",
            ) as handle:
                output = _write_output(
                    handle, bundle.oracle.state.output
                )
                alias = handle.workspace / "alias"
                os.link(output, alias)
                self.assertFalse(
                    verify_jsonl_csv_enrichment_compose_workspace(
                        task, profile, bundle, handle
                    )
                )

    def test_workspace_symlink_target_mutation_fails(self) -> None:
        task = TASK_BY_CELL[
            ("jsonl-left-csv-right", "drop-row")
        ]
        profile = PROFILE_BY_ID["symlinks-ordering"]
        bundle = build_jsonl_csv_enrichment_compose_fixture_bundle(
            task, profile
        )
        self.assertTrue(
            any(
                type(item) is InputSymlink
                for item in bundle.definition.inputs
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_jsonl_csv_enrichment_compose_fixture(
                task,
                profile,
                bundle,
                Path(temporary) / "workspace",
            ) as handle:
                _write_output(handle, bundle.oracle.state.output)
                link = (
                    handle.workspace / "input/distractors/link"
                )
                link.unlink()
                os.symlink("changed-target", link)
                self.assertFalse(
                    verify_jsonl_csv_enrichment_compose_workspace(
                        task, profile, bundle, handle
                    )
                )


if __name__ == "__main__":
    unittest.main()
