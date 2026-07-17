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
from cbds.executable_nested_json_schema_migration import (
    NESTED_JSON_SCHEMA_MIGRATION_ALLOWED_TOOLS,
    NESTED_JSON_SCHEMA_MIGRATION_ATOMICITY_OBSERVED,
    NESTED_JSON_SCHEMA_MIGRATION_CANDIDATE_EXIT_STATUS_OBSERVED,
    NESTED_JSON_SCHEMA_MIGRATION_DOCUMENT_OUTPUT_MAXIMUM_BYTES,
    NESTED_JSON_SCHEMA_MIGRATION_FAMILY_ID,
    NESTED_JSON_SCHEMA_MIGRATION_FINAL_OUTPUT_OBSERVED,
    NESTED_JSON_SCHEMA_MIGRATION_INPUT,
    NESTED_JSON_SCHEMA_MIGRATION_INPUT_PRESERVATION_OBSERVED,
    NESTED_JSON_SCHEMA_MIGRATION_INPUT_SHAPES,
    NESTED_JSON_SCHEMA_MIGRATION_MANIFEST_OUTPUT_MAXIMUM_BYTES,
    NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DEPTH,
    NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DOCUMENTS,
    NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_NODES,
    NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_MANIFEST,
    NESTED_JSON_SCHEMA_MIGRATION_POLICIES,
    NESTED_JSON_SCHEMA_MIGRATION_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES,
    NESTED_JSON_SCHEMA_MIGRATION_READ_SCOPE_OBSERVED,
    NESTED_JSON_SCHEMA_MIGRATION_SCALAR_MAXIMUM_UTF8_BYTES,
    NESTED_JSON_SCHEMA_MIGRATION_SOURCE_MAXIMUM_BYTES,
    NESTED_JSON_SCHEMA_MIGRATION_TOOL_HISTORY_OBSERVED,
    NESTED_JSON_SCHEMA_MIGRATION_TRANSIENT_STATE_OBSERVED,
    NESTED_JSON_SCHEMA_MIGRATION_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
    NESTED_JSON_SCHEMA_MIGRATION_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE,
    NestedJsonSchemaMigrationError,
    NestedJsonSchemaMigrationParameters,
    build_nested_json_schema_migration_fixture_bundle,
    build_nested_json_schema_migration_tasks,
    compute_nested_json_schema_migration_discrimination_sha256,
    compute_nested_json_schema_migration_proved_output_bound,
    derive_nested_json_schema_migration_state,
    materialize_nested_json_schema_migration_fixture,
    nested_json_schema_migration_task_semantic_core,
    parse_nested_json_schema_migration_document_output,
    parse_nested_json_schema_migration_manifest_output,
    parse_nested_json_schema_migration_source,
    reference_nested_json_schema_migration_state,
    validate_nested_json_schema_migration_fixture_bundle,
    validate_nested_json_schema_migration_fixture_for_task_profile,
    verify_nested_json_schema_migration_fixture_bundle,
    verify_nested_json_schema_migration_fixture_for_task_profile,
    verify_nested_json_schema_migration_workspace,
)
from cbds.executable_static_types import OpaqueFixtureDescriptor
from cbds.executable_workspace import (
    FixtureDefinition,
    InputFile,
    InputSymlink,
    MAX_TOTAL_BYTES,
)


TASKS = build_nested_json_schema_migration_tasks()
TASK_BY_CELL = {
    (
        task.parameters.input_shape,
        task.parameters.migration_policy,
    ): task
    for task in TASKS
}
PROFILE_BY_ID = {
    profile.profile_id: profile
    for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
}
EXPECTED_DISCRIMINATION_SHA256 = (
    "416907543c373f36e55098c514fbe17aeef0192d9e5dc43cd025bed809a0ad42"
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


def _v1_document(
    record_id: str = "record",
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "record_id": record_id,
        "profile": {
            "display_name": "Display",
            "enabled": "yes",
            "limits": {"quota": "7"},
            "contact": {"email": "user@example.test"},
            "deprecated_code": "old-code",
        },
        "tags": "one tag",
        "deprecated": {"note": "old-note"},
    }


def _definition(
    value: object | None = None,
    *,
    shape: str = "single-object",
    payload: bytes | None = None,
) -> FixtureDefinition:
    if payload is None:
        selected = _v1_document() if value is None else value
        if shape == "jsonl-objects":
            if type(selected) is list:
                payload = b"".join(_json_bytes(item) for item in selected)
            else:
                payload = _json_bytes(selected)
        else:
            payload = _json_bytes(selected)
    return FixtureDefinition(
        "fixture.nested-json-policy-example",
        (
            InputFile(
                NESTED_JSON_SCHEMA_MIGRATION_INPUT,
                payload,
                0o600,
                100,
            ),
        ),
        (),
    )


def _write_state(handle: object, state: object) -> None:
    output = handle.workspace / "output"
    documents = output / "documents"
    documents.mkdir(parents=True, exist_ok=True)
    output.chmod(0o755)
    documents.chmod(0o755)
    manifest = output / "manifest.json"
    manifest.write_bytes(state.manifest)
    manifest.chmod(0o644)
    for document in state.documents:
        path = output / document.file
        path.write_bytes(document.content)
        path.chmod(0o644)


class NestedJsonSchemaMigrationTaskTests(unittest.TestCase):
    def test_grid_is_exact_unique_public_and_discriminable(self) -> None:
        expected = tuple(
            (shape, policy)
            for shape in NESTED_JSON_SCHEMA_MIGRATION_INPUT_SHAPES
            for policy in NESTED_JSON_SCHEMA_MIGRATION_POLICIES
        )
        self.assertEqual(len(TASKS), 20)
        self.assertEqual(
            tuple(
                (
                    task.parameters.input_shape,
                    task.parameters.migration_policy,
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
            compute_nested_json_schema_migration_discrimination_sha256(
                TASKS
            ),
            EXPECTED_DISCRIMINATION_SHA256,
        )
        for task in TASKS:
            with self.subTest(task=task.task_id):
                task.__post_init__()
                self.assertEqual(
                    task.family_id,
                    NESTED_JSON_SCHEMA_MIGRATION_FAMILY_ID,
                )
                self.assertEqual(
                    task.allowed_tools,
                    NESTED_JSON_SCHEMA_MIGRATION_ALLOWED_TOOLS,
                )
                self.assertEqual(len(task.fixtures), 5)
                self.assertTrue(task.public)
                self.assertFalse(task.sealed)
                self.assertFalse(task.candidate_execution_authorized)
                self.assertFalse(task.model_selection_eligible)
                self.assertFalse(task.claim_authorized)
                semantic = (
                    nested_json_schema_migration_task_semantic_core(
                        task.parameters, task.prompt, task.graph
                    )
                )
                self.assertEqual(
                    semantic["family_id"],
                    NESTED_JSON_SCHEMA_MIGRATION_FAMILY_ID,
                )
                self.assertIn("Preserve every other allowed field", task.prompt)

    def test_outcome_signatures_are_axis_label_free_and_unique(self) -> None:
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        signatures: set[tuple[str, tuple[str, ...]]] = set()
        for task in TASKS:
            bundle = build_nested_json_schema_migration_fixture_bundle(
                task, profile
            )
            source = next(
                item
                for item in bundle.definition.inputs
                if type(item) is InputFile
                and item.path == NESTED_JSON_SCHEMA_MIGRATION_INPUT
            )
            signatures.add(
                (
                    sha256(source.content).hexdigest(),
                    tuple(
                        sha256(document.content).hexdigest()
                        for document in bundle.oracle.state.documents
                    ),
                )
            )
        self.assertEqual(len(signatures), 20)

    def test_task_and_authority_mutations_fail_closed(self) -> None:
        task = TASKS[0]
        with self.assertRaises(NestedJsonSchemaMigrationError):
            NestedJsonSchemaMigrationParameters(  # type: ignore[arg-type]
                "invented", "rename-fields"
            )
        with self.assertRaises(NestedJsonSchemaMigrationError):
            NestedJsonSchemaMigrationParameters(  # type: ignore[arg-type]
                "single-object", "invented"
            )
        with self.assertRaises(NestedJsonSchemaMigrationError):
            replace(task, prompt=task.prompt + " ")
        with self.assertRaises(NestedJsonSchemaMigrationError):
            replace(task, candidate_execution_authorized=True)
        with self.assertRaises(NestedJsonSchemaMigrationError):
            replace(task, allowed_tools=task.allowed_tools + ("cat",))
        with self.assertRaises(NestedJsonSchemaMigrationError):
            replace(task, fixtures=(task.fixtures[0],) * 5)

    def test_observation_boundary_and_no_production_asserts(self) -> None:
        self.assertTrue(NESTED_JSON_SCHEMA_MIGRATION_FINAL_OUTPUT_OBSERVED)
        self.assertTrue(
            NESTED_JSON_SCHEMA_MIGRATION_INPUT_PRESERVATION_OBSERVED
        )
        self.assertTrue(
            NESTED_JSON_SCHEMA_MIGRATION_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE
        )
        for value in (
            NESTED_JSON_SCHEMA_MIGRATION_ATOMICITY_OBSERVED,
            NESTED_JSON_SCHEMA_MIGRATION_TOOL_HISTORY_OBSERVED,
            NESTED_JSON_SCHEMA_MIGRATION_READ_SCOPE_OBSERVED,
            NESTED_JSON_SCHEMA_MIGRATION_CANDIDATE_EXIT_STATUS_OBSERVED,
            NESTED_JSON_SCHEMA_MIGRATION_TRANSIENT_STATE_OBSERVED,
            NESTED_JSON_SCHEMA_MIGRATION_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
        ):
            self.assertFalse(value)
        source_path = (
            ROOT
            / "src"
            / "cbds"
            / "executable_nested_json_schema_migration.py"
        )
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        self.assertFalse(
            any(isinstance(node, ast.Assert) for node in ast.walk(tree))
        )


class NestedJsonSchemaMigrationPolicyTests(unittest.TestCase):
    def _state(self, policy: str) -> dict[str, object]:
        parameters = NestedJsonSchemaMigrationParameters(
            "single-object", policy  # type: ignore[arg-type]
        )
        definition = _definition()
        primary = derive_nested_json_schema_migration_state(
            definition, parameters
        )
        reference = reference_nested_json_schema_migration_state(
            definition, parameters
        )
        self.assertEqual(primary, reference)
        return primary.documents[0].value

    def test_each_policy_has_exact_independent_effect(self) -> None:
        renamed = self._state("rename-fields")
        self.assertEqual(renamed["schema_version"], 2)
        self.assertEqual(renamed["id"], "record")
        self.assertNotIn("record_id", renamed)
        renamed_profile = renamed["profile"]
        self.assertEqual(renamed_profile["name"], "Display")
        self.assertEqual(renamed_profile["enabled"], "yes")
        self.assertIn("limits", renamed_profile)
        self.assertIn("contact", renamed_profile)
        self.assertIn("deprecated_code", renamed_profile)
        self.assertEqual(renamed["tags"], "one tag")
        self.assertIn("deprecated", renamed)

        normalized = self._state("normalize-types")
        self.assertEqual(normalized["record_id"], "record")
        normalized_profile = normalized["profile"]
        self.assertEqual(normalized_profile["display_name"], "Display")
        self.assertIs(normalized_profile["enabled"], True)
        self.assertEqual(normalized_profile["limits"]["quota"], 7)
        self.assertEqual(normalized["tags"], ["one tag"])
        self.assertIn("contact", normalized_profile)
        self.assertIn("deprecated", normalized)

        lifted = self._state("lift-nested-members")
        lifted_profile = lifted["profile"]
        self.assertEqual(lifted["email"], "user@example.test")
        self.assertEqual(lifted["quota"], "7")
        self.assertNotIn("contact", lifted_profile)
        self.assertNotIn("limits", lifted_profile)
        self.assertEqual(lifted_profile["enabled"], "yes")
        self.assertEqual(lifted["tags"], "one tag")
        self.assertIn("deprecated_code", lifted_profile)

        dropped = self._state("drop-deprecated-members")
        dropped_profile = dropped["profile"]
        self.assertNotIn("deprecated", dropped)
        self.assertNotIn("deprecated_code", dropped_profile)
        self.assertIn("contact", dropped_profile)
        self.assertIn("limits", dropped_profile)
        self.assertEqual(dropped["tags"], "one tag")

        combined = self._state("combined-version-upgrade")
        combined_profile = combined["profile"]
        self.assertEqual(combined["id"], "record")
        self.assertEqual(combined_profile["name"], "Display")
        self.assertIs(combined_profile["enabled"], True)
        self.assertEqual(combined["quota"], 7)
        self.assertEqual(combined["email"], "user@example.test")
        self.assertEqual(combined["tags"], ["one tag"])
        for absent in ("record_id", "deprecated"):
            self.assertNotIn(absent, combined)
        for absent in (
            "display_name",
            "limits",
            "contact",
            "deprecated_code",
        ):
            self.assertNotIn(absent, combined_profile)

    def test_normalization_accepts_every_closed_token_exactly(self) -> None:
        cases = (
            (True, True),
            (False, False),
            (1, True),
            (0, False),
            ("true", True),
            ("yes", True),
            ("1", True),
            ("false", False),
            ("no", False),
            ("0", False),
        )
        for source, expected in cases:
            with self.subTest(source=source):
                document = _v1_document()
                document["profile"]["enabled"] = source
                parameters = NestedJsonSchemaMigrationParameters(
                    "single-object", "normalize-types"
                )
                state = derive_nested_json_schema_migration_state(
                    _definition(document), parameters
                )
                self.assertIs(
                    state.documents[0].value["profile"]["enabled"],
                    expected,
                )


class NestedJsonSchemaMigrationFixtureTests(unittest.TestCase):
    def test_task_state_oracle_and_bundle_require_exact_owned_types(
        self,
    ) -> None:
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
        text_fields = (
            "family_id",
            "family_version",
            "filesystem_identity",
            "output_identity",
            "split_role",
        )
        for field_name in text_fields:
            with self.subTest(task_field=field_name):
                with self.assertRaises(NestedJsonSchemaMigrationError):
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
            with self.subTest(tools_type=type(hostile_tools).__name__):
                with self.assertRaises(NestedJsonSchemaMigrationError):
                    replace(task, allowed_tools=hostile_tools)

        bundle = build_nested_json_schema_migration_fixture_bundle(
            task, PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        )
        document = bundle.oracle.state.documents[0]
        with self.assertRaises(NestedJsonSchemaMigrationError):
            replace(document, file=StringSubclass(document.file))
        with self.assertRaises(NestedJsonSchemaMigrationError):
            replace(bundle.oracle, state=StateProxy(bundle.oracle.state))
        for field_name in ("semantic_verifier_identity", "schema_version"):
            with self.subTest(oracle_field=field_name):
                with self.assertRaises(NestedJsonSchemaMigrationError):
                    replace(
                        bundle.oracle,
                        **{
                            field_name: StringSubclass(
                                getattr(bundle.oracle, field_name)
                            )
                        },
                    )
        with self.assertRaises(NestedJsonSchemaMigrationError):
            replace(
                bundle,
                schema_version=StringSubclass(bundle.schema_version),
            )

    def test_spaces_unicode_fixture_round_trips_json_escapes(self) -> None:
        task = TASK_BY_CELL[
            ("single-object", "combined-version-upgrade")
        ]
        bundle = build_nested_json_schema_migration_fixture_bundle(
            task, PROFILE_BY_ID["spaces-unicode"]
        )
        source = next(
            item.content
            for item in bundle.definition.inputs
            if (
                isinstance(item, InputFile)
                and item.path == NESTED_JSON_SCHEMA_MIGRATION_INPUT
            )
        )
        self.assertIn(b'\\"', source)
        self.assertIn(b"\\\\", source)
        parsed = parse_nested_json_schema_migration_source(
            source, "single-object"
        )
        self.assertEqual(
            parsed[0]["profile"]["display_name"],
            'Snow "雪" \\ User',
        )
        migrated = bundle.oracle.state.documents[0]
        self.assertEqual(
            migrated.value["profile"]["name"],
            'Snow "雪" \\ User',
        )
        self.assertIn(b'\\"', migrated.content)
        self.assertIn(b"\\\\", migrated.content)

    def test_all_100_bundles_reconstruct_with_independent_oracles(self) -> None:
        fixture_ids: set[str] = set()
        count = 0
        for task in TASKS:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                with self.subTest(
                    shape=task.parameters.input_shape,
                    policy=task.parameters.migration_policy,
                    profile=profile.profile_id,
                ):
                    bundle = (
                        build_nested_json_schema_migration_fixture_bundle(
                            task, profile
                        )
                    )
                    validate_nested_json_schema_migration_fixture_bundle(
                        bundle
                    )
                    validate_nested_json_schema_migration_fixture_for_task_profile(
                        task, profile, bundle
                    )
                    self.assertTrue(
                        verify_nested_json_schema_migration_fixture_bundle(
                            bundle
                        )
                    )
                    self.assertTrue(
                        verify_nested_json_schema_migration_fixture_for_task_profile(
                            task, profile, bundle
                        )
                    )
                    primary = derive_nested_json_schema_migration_state(
                        bundle.definition, task.parameters
                    )
                    reference = (
                        reference_nested_json_schema_migration_state(
                            bundle.definition, task.parameters
                        )
                    )
                    self.assertEqual(primary, reference)
                    self.assertEqual(primary, bundle.oracle.state)
                    self.assertEqual(
                        parse_nested_json_schema_migration_manifest_output(
                            primary.manifest
                        ),
                        primary.manifest,
                    )
                    for document in primary.documents:
                        self.assertEqual(
                            parse_nested_json_schema_migration_document_output(
                                document.content
                            ),
                            document.content,
                        )
                    fixture_ids.add(bundle.descriptor.fixture_sha256)
                    count += 1
        self.assertEqual(count, 100)
        self.assertEqual(len(fixture_ids), 100)

    def test_bundle_binding_and_authority_mutations_fail_closed(self) -> None:
        task = TASKS[0]
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        bundle = build_nested_json_schema_migration_fixture_bundle(
            task, profile
        )
        with self.assertRaises(NestedJsonSchemaMigrationError):
            replace(bundle, candidate_execution_authorized=True)
        with self.assertRaises(NestedJsonSchemaMigrationError):
            replace(bundle, fixture_definition_sha256="0" * 64)
        with self.assertRaises(NestedJsonSchemaMigrationError):
            replace(
                bundle,
                descriptor=OpaqueFixtureDescriptor(
                    "fx-" + "0" * 24,
                    "0" * 64,
                    bundle.task_contract_sha256,
                ),
            )
        self.assertFalse(
            verify_nested_json_schema_migration_fixture_bundle(object())
        )
        corrupted = copy.copy(bundle)
        object.__delattr__(corrupted, "oracle")
        self.assertFalse(
            verify_nested_json_schema_migration_fixture_bundle(corrupted)
        )
        self.assertFalse(
            verify_nested_json_schema_migration_fixture_for_task_profile(
                task, profile, corrupted
            )
        )


class NestedJsonSchemaMigrationSourceParserTests(unittest.TestCase):
    def test_all_four_shapes_and_raw_utf8_map_order(self) -> None:
        first = _v1_document("é")
        second = _v1_document("z")
        third = _v1_document("雪")
        documents = [first, second, third]
        single = parse_nested_json_schema_migration_source(
            _json_bytes(first), "single-object"
        )
        self.assertEqual([item["record_id"] for item in single], ["é"])
        array = parse_nested_json_schema_migration_source(
            _json_bytes(documents), "object-array"
        )
        self.assertEqual(
            [item["record_id"] for item in array], ["é", "z", "雪"]
        )
        mapped = {"雪": third, "é": first, "z": second}
        mapped_payload = _json_bytes(mapped, canonical=False)
        physical_pairs = json.loads(
            mapped_payload,
            object_pairs_hook=lambda pairs: pairs,
        )
        self.assertEqual(
            [key for key, _value in physical_pairs],
            ["雪", "é", "z"],
        )
        ordered = parse_nested_json_schema_migration_source(
            mapped_payload, "keyed-object-map"
        )
        self.assertEqual(
            [item["record_id"] for item in ordered], ["z", "é", "雪"]
        )
        jsonl = parse_nested_json_schema_migration_source(
            b"".join(_json_bytes(item) for item in documents),
            "jsonl-objects",
        )
        self.assertEqual(
            [item["record_id"] for item in jsonl], ["é", "z", "雪"]
        )
        first["record_id"] = "mutated"
        self.assertEqual(single[0]["record_id"], "é")

    def test_every_keyed_map_fixture_requires_semantic_key_sorting(
        self,
    ) -> None:
        task = TASK_BY_CELL[("keyed-object-map", "rename-fields")]
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
            with self.subTest(profile=profile.profile_id):
                bundle = build_nested_json_schema_migration_fixture_bundle(
                    task, profile
                )
                source = next(
                    item.content
                    for item in bundle.definition.inputs
                    if (
                        isinstance(item, InputFile)
                        and item.path
                        == NESTED_JSON_SCHEMA_MIGRATION_INPUT
                    )
                )
                physical_pairs = json.loads(
                    source,
                    object_pairs_hook=lambda pairs: pairs,
                )
                physical_keys = [
                    key for key, _value in physical_pairs
                ]
                semantic_keys = sorted(
                    physical_keys,
                    key=lambda value: value.encode("utf-8"),
                )
                self.assertNotEqual(physical_keys, semantic_keys)
                parsed = parse_nested_json_schema_migration_source(
                    source, "keyed-object-map"
                )
                self.assertEqual(
                    [item["record_id"] for item in parsed],
                    semantic_keys,
                )

    def test_source_fails_closed_on_schema_types_and_json_grammar(self) -> None:
        valid = _v1_document()
        invalid_values: list[object] = []
        for mutation in (
            {"extra": True},
            {"schema_version": True},
            {"schema_version": 2},
            {"record_id": ""},
            {"record_id": 1},
            {"profile": {"display_name": "x", "enabled": 2}},
            {"tags": ["x"] * 17},
            {"deprecated": {"note": "x", "extra": "y"}},
        ):
            value = copy.deepcopy(valid)
            if set(mutation) == {"profile"}:
                value["profile"] = mutation["profile"]
            else:
                value.update(mutation)
            invalid_values.append(value)
        bad_quota = copy.deepcopy(valid)
        bad_quota["profile"]["limits"]["quota"] = "01"
        invalid_values.append(bad_quota)
        negative_zero = copy.deepcopy(valid)
        negative_zero["profile"]["limits"]["quota"] = "-0"
        invalid_values.append(negative_zero)
        bad_control = copy.deepcopy(valid)
        bad_control["profile"]["display_name"] = "bad\nname"
        invalid_values.append(bad_control)
        unicode_control = copy.deepcopy(valid)
        unicode_control["profile"]["display_name"] = "bad\u0085name"
        invalid_values.append(unicode_control)
        unicode_format_control = copy.deepcopy(valid)
        unicode_format_control["profile"]["display_name"] = "bad\u200bname"
        invalid_values.append(unicode_format_control)
        too_long = copy.deepcopy(valid)
        too_long["record_id"] = (
            "x"
            * (
                NESTED_JSON_SCHEMA_MIGRATION_SCALAR_MAXIMUM_UTF8_BYTES
                + 1
            )
        )
        invalid_values.append(too_long)

        for value in invalid_values:
            with self.subTest(value=str(value)[:80]):
                with self.assertRaises(NestedJsonSchemaMigrationError):
                    parse_nested_json_schema_migration_source(
                        _json_bytes(value), "single-object"
                    )

        malformed = (
            _json_bytes(valid)[:-1],
            b"\xef\xbb\xbf" + _json_bytes(valid),
            b"\xff\n",
            b'{"schema_version":1,"schema_version":1}\n',
            b'{"schema_version":1e0}\n',
            b'{"schema_version":NaN}\n',
            b'{"schema_version":10000000}\n',
            b"[" * (NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DEPTH + 1)
            + b"0"
            + b"]" * (NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DEPTH + 1)
            + b"\n",
            _json_bytes(
                [None] * (NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_NODES + 1)
            ),
        )
        for payload in malformed:
            with self.subTest(payload=payload[:60]):
                with self.assertRaises(NestedJsonSchemaMigrationError):
                    parse_nested_json_schema_migration_source(
                        payload, "single-object"
                    )

    def test_shape_specific_framing_and_map_binding_fail_closed(self) -> None:
        document = _v1_document("key")
        invalid = (
            (_json_bytes([]), "object-array"),
            (_json_bytes([document]), "single-object"),
            (_json_bytes({"wrong": document}), "keyed-object-map"),
            (_json_bytes(document) + b"\n", "jsonl-objects"),
            (_json_bytes(document)[:-1], "jsonl-objects"),
            (b"\n", "jsonl-objects"),
            (_json_bytes(document).replace(b"\n", b"\r\n"), "jsonl-objects"),
        )
        for payload, shape in invalid:
            with self.subTest(shape=shape, payload=payload[:50]):
                with self.assertRaises(NestedJsonSchemaMigrationError):
                    parse_nested_json_schema_migration_source(
                        payload, shape  # type: ignore[arg-type]
                    )

    def test_maximum_document_count_is_exact(self) -> None:
        accepted = [
            _v1_document(f"r-{index:02d}")
            for index in range(
                NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DOCUMENTS
            )
        ]
        self.assertEqual(
            len(
                parse_nested_json_schema_migration_source(
                    _json_bytes(accepted), "object-array"
                )
            ),
            NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DOCUMENTS,
        )
        rejected = accepted + [_v1_document("one-too-many")]
        with self.assertRaises(NestedJsonSchemaMigrationError):
            parse_nested_json_schema_migration_source(
                _json_bytes(rejected), "object-array"
            )

    def test_source_and_multibyte_scalar_boundaries_are_exact(self) -> None:
        boundary = ("雪" * 42) + "ab"
        oversized = boundary + "b"
        self.assertEqual(
            len(boundary.encode("utf-8")),
            NESTED_JSON_SCHEMA_MIGRATION_SCALAR_MAXIMUM_UTF8_BYTES,
        )
        self.assertEqual(
            len(oversized.encode("utf-8")),
            NESTED_JSON_SCHEMA_MIGRATION_SCALAR_MAXIMUM_UTF8_BYTES + 1,
        )
        accepted_document = _v1_document(boundary)
        self.assertEqual(
            parse_nested_json_schema_migration_source(
                _json_bytes(accepted_document),
                "single-object",
            )[0]["record_id"],
            boundary,
        )
        rejected_document = _v1_document(oversized)
        with self.assertRaises(NestedJsonSchemaMigrationError):
            parse_nested_json_schema_migration_source(
                _json_bytes(rejected_document),
                "single-object",
            )

        compact = _json_bytes(_v1_document())
        padding = (
            NESTED_JSON_SCHEMA_MIGRATION_SOURCE_MAXIMUM_BYTES
            - len(compact)
        )
        self.assertGreater(padding, 0)
        maximum = compact[:-1] + (b" " * padding) + b"\n"
        self.assertEqual(
            len(maximum),
            NESTED_JSON_SCHEMA_MIGRATION_SOURCE_MAXIMUM_BYTES,
        )
        self.assertEqual(
            len(
                parse_nested_json_schema_migration_source(
                    maximum,
                    "single-object",
                )
            ),
            1,
        )
        with self.assertRaises(NestedJsonSchemaMigrationError):
            parse_nested_json_schema_migration_source(
                maximum[:-1] + b" \n",
                "single-object",
            )

    def test_nested_duplicates_surrogates_and_bool_quota_fail_closed(
        self,
    ) -> None:
        duplicate_nested = (
            b'{"profile":{"contact":{"email":"a","email":"b"},'
            b'"display_name":"n","enabled":true},'
            b'"record_id":"r","schema_version":1}\n'
        )
        lone_surrogate = (
            b'{"profile":{"display_name":"\\ud800","enabled":true},'
            b'"record_id":"r","schema_version":1}\n'
        )
        bool_quota = (
            b'{"profile":{"display_name":"n","enabled":true,'
            b'"limits":{"quota":true}},'
            b'"record_id":"r","schema_version":1}\n'
        )
        for payload in (duplicate_nested, lone_surrogate, bool_quota):
            with self.subTest(payload=payload):
                with self.assertRaises(NestedJsonSchemaMigrationError):
                    parse_nested_json_schema_migration_source(
                        payload,
                        "single-object",
                    )


class NestedJsonSchemaMigrationOutputTests(unittest.TestCase):
    def test_semantic_json_format_and_key_order_are_accepted(self) -> None:
        task = TASK_BY_CELL[
            ("object-array", "combined-version-upgrade")
        ]
        bundle = build_nested_json_schema_migration_fixture_bundle(
            task, PROFILE_BY_ID["spaces-unicode"]
        )
        state = bundle.oracle.state
        manifest_value = json.loads(state.manifest)
        varied_manifest = _json_bytes(
            dict(reversed(list(manifest_value.items()))),
            canonical=False,
        )
        self.assertEqual(
            parse_nested_json_schema_migration_manifest_output(
                varied_manifest
            ),
            state.manifest,
        )
        for document in state.documents:
            value = json.loads(document.content)
            varied = _json_bytes(
                dict(reversed(list(value.items()))),
                canonical=False,
            )
            self.assertEqual(
                parse_nested_json_schema_migration_document_output(
                    varied
                ),
                document.content,
            )

    def test_document_output_rejects_duplicate_extra_type_and_bound(self) -> None:
        valid = {
            "schema_version": 2,
            "record_id": "r",
            "profile": {
                "display_name": "n",
                "enabled": True,
            },
        }
        invalid = (
            b'{"schema_version":2,"schema_version":2}\n',
            _json_bytes({**valid, "extra": 1}),
            _json_bytes({**valid, "schema_version": True}),
            _json_bytes(
                {
                    **valid,
                    "id": "r",
                }
            ),
            _json_bytes(
                {
                    **valid,
                    "profile": {
                        "display_name": "n",
                        "name": "n",
                        "enabled": True,
                    },
                }
            ),
            b"x"
            * (
                NESTED_JSON_SCHEMA_MIGRATION_DOCUMENT_OUTPUT_MAXIMUM_BYTES
                + 1
            ),
        )
        for payload in invalid:
            with self.subTest(payload=payload[:60]):
                with self.assertRaises(NestedJsonSchemaMigrationError):
                    parse_nested_json_schema_migration_document_output(
                        payload
                    )

    def test_manifest_rejects_extra_type_order_and_shape_mutations(self) -> None:
        task = TASK_BY_CELL[
            ("keyed-object-map", "rename-fields")
        ]
        bundle = build_nested_json_schema_migration_fixture_bundle(
            task, PROFILE_BY_ID["symlinks-ordering"]
        )
        manifest = json.loads(bundle.oracle.state.manifest)
        mutations: list[dict[str, object]] = []
        extra = copy.deepcopy(manifest)
        extra["extra"] = 1
        mutations.append(extra)
        bool_count = copy.deepcopy(manifest)
        bool_count["document_count"] = True
        mutations.append(bool_count)
        wrong_file = copy.deepcopy(manifest)
        wrong_file["entries"][0]["file"] = "documents/000001.json"
        mutations.append(wrong_file)
        wrong_index = copy.deepcopy(manifest)
        wrong_index["entries"][0]["source_index"] = 1
        mutations.append(wrong_index)
        reversed_entries = copy.deepcopy(manifest)
        reversed_entries["entries"].reverse()
        mutations.append(reversed_entries)
        wrong_key = copy.deepcopy(manifest)
        wrong_key["entries"][0]["source_key"] = None
        mutations.append(wrong_key)
        for value in mutations:
            with self.subTest(value=str(value)[:100]):
                with self.assertRaises(NestedJsonSchemaMigrationError):
                    parse_nested_json_schema_migration_manifest_output(
                        _json_bytes(value)
                    )
        with self.assertRaises(NestedJsonSchemaMigrationError):
            parse_nested_json_schema_migration_manifest_output(
                b"x"
                * (
                    NESTED_JSON_SCHEMA_MIGRATION_MANIFEST_OUTPUT_MAXIMUM_BYTES
                    + 1
                )
            )


class NestedJsonSchemaMigrationBoundsTests(unittest.TestCase):
    def test_conservative_output_bound_is_explicit_and_workspace_safe(
        self,
    ) -> None:
        reconstructed = (
            NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DOCUMENTS
            * NESTED_JSON_SCHEMA_MIGRATION_DOCUMENT_OUTPUT_MAXIMUM_BYTES
            + NESTED_JSON_SCHEMA_MIGRATION_MANIFEST_OUTPUT_MAXIMUM_BYTES
        )
        self.assertEqual(
            compute_nested_json_schema_migration_proved_output_bound(),
            reconstructed,
        )
        self.assertEqual(
            reconstructed,
            NESTED_JSON_SCHEMA_MIGRATION_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES,
        )
        self.assertLess(reconstructed, MAX_TOTAL_BYTES)

    def test_source_mutation_changes_both_oracles_or_fails_both(self) -> None:
        task = TASK_BY_CELL[
            ("single-object", "combined-version-upgrade")
        ]
        bundle = build_nested_json_schema_migration_fixture_bundle(
            task, PROFILE_BY_ID["spaces-unicode"]
        )
        inputs = list(bundle.definition.inputs)
        index = next(
            index
            for index, item in enumerate(inputs)
            if type(item) is InputFile
            and item.path == NESTED_JSON_SCHEMA_MIGRATION_INPUT
        )
        source = inputs[index]
        self.assertIs(type(source), InputFile)
        source_value = json.loads(source.content)
        source_value["profile"]["display_name"] = "Changed User"
        inputs[index] = replace(
            source,
            content=_json_bytes(source_value),
        )
        mutated = FixtureDefinition(
            bundle.definition.fixture_id,
            tuple(inputs),
            bundle.definition.expected_files,
        )
        primary = derive_nested_json_schema_migration_state(
            mutated, task.parameters
        )
        reference = reference_nested_json_schema_migration_state(
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
        with self.assertRaises(NestedJsonSchemaMigrationError):
            derive_nested_json_schema_migration_state(
                malformed, task.parameters
            )
        with self.assertRaises(NestedJsonSchemaMigrationError):
            reference_nested_json_schema_migration_state(
                malformed, task.parameters
            )


class NestedJsonSchemaMigrationWorkspaceTests(unittest.TestCase):
    def test_all_100_task_profile_oracles_pass_workspace_verifier(
        self,
    ) -> None:
        for task in TASKS:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                with self.subTest(
                    shape=task.parameters.input_shape,
                    policy=task.parameters.migration_policy,
                    profile=profile.profile_id,
                ), tempfile.TemporaryDirectory() as temporary:
                    bundle = (
                        build_nested_json_schema_migration_fixture_bundle(
                            task, profile
                        )
                    )
                    with materialize_nested_json_schema_migration_fixture(
                        task,
                        profile,
                        bundle,
                        Path(temporary) / "workspace",
                    ) as handle:
                        _write_state(handle, bundle.oracle.state)
                        self.assertTrue(
                            verify_nested_json_schema_migration_workspace(
                                task, profile, bundle, handle
                            )
                        )

    def test_workspace_accepts_semantic_formatting(self) -> None:
        task = TASK_BY_CELL[
            ("object-array", "combined-version-upgrade")
        ]
        profile = PROFILE_BY_ID["spaces-unicode"]
        bundle = build_nested_json_schema_migration_fixture_bundle(
            task, profile
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_nested_json_schema_migration_fixture(
                task,
                profile,
                bundle,
                Path(temporary) / "workspace",
            ) as handle:
                _write_state(handle, bundle.oracle.state)
                manifest = (
                    handle.workspace
                    / NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_MANIFEST
                )
                value = json.loads(manifest.read_bytes())
                manifest.write_bytes(
                    _json_bytes(
                        dict(reversed(list(value.items()))),
                        canonical=False,
                    )
                )
                for document in bundle.oracle.state.documents:
                    path = handle.workspace / f"output/{document.file}"
                    value = json.loads(path.read_bytes())
                    path.write_bytes(
                        _json_bytes(
                            dict(reversed(list(value.items()))),
                            canonical=False,
                        )
                    )
                self.assertTrue(
                    verify_nested_json_schema_migration_workspace(
                        task, profile, bundle, handle
                    )
                )

    def test_workspace_rejects_tree_semantic_mode_and_input_mutations(
        self,
    ) -> None:
        task = TASK_BY_CELL[
            ("keyed-object-map", "lift-nested-members")
        ]
        profile = PROFILE_BY_ID["symlinks-ordering"]
        bundle = build_nested_json_schema_migration_fixture_bundle(
            task, profile
        )

        with tempfile.TemporaryDirectory() as temporary:
            with materialize_nested_json_schema_migration_fixture(
                task, profile, bundle, Path(temporary) / "workspace"
            ) as handle:
                _write_state(handle, bundle.oracle.state)
                document = handle.workspace / "output/documents/000000.json"
                value = json.loads(document.read_bytes())
                value["email"] = "changed@example.test"
                document.write_bytes(_json_bytes(value))
                self.assertFalse(
                    verify_nested_json_schema_migration_workspace(
                        task, profile, bundle, handle
                    )
                )

        with tempfile.TemporaryDirectory() as temporary:
            with materialize_nested_json_schema_migration_fixture(
                task, profile, bundle, Path(temporary) / "workspace"
            ) as handle:
                _write_state(handle, bundle.oracle.state)
                manifest = handle.workspace / "output/manifest.json"
                value = json.loads(manifest.read_bytes())
                value["entries"].reverse()
                manifest.write_bytes(_json_bytes(value))
                self.assertFalse(
                    verify_nested_json_schema_migration_workspace(
                        task, profile, bundle, handle
                    )
                )

        with tempfile.TemporaryDirectory() as temporary:
            with materialize_nested_json_schema_migration_fixture(
                task, profile, bundle, Path(temporary) / "workspace"
            ) as handle:
                _write_state(handle, bundle.oracle.state)
                document = handle.workspace / "output/documents/000000.json"
                document.chmod(0o600)
                self.assertFalse(
                    verify_nested_json_schema_migration_workspace(
                        task, profile, bundle, handle
                    )
                )

        with tempfile.TemporaryDirectory() as temporary:
            with materialize_nested_json_schema_migration_fixture(
                task, profile, bundle, Path(temporary) / "workspace"
            ) as handle:
                _write_state(handle, bundle.oracle.state)
                extra = handle.workspace / "output/extra"
                extra.write_bytes(b"unexpected")
                self.assertFalse(
                    verify_nested_json_schema_migration_workspace(
                        task, profile, bundle, handle
                    )
                )

        with tempfile.TemporaryDirectory() as temporary:
            with materialize_nested_json_schema_migration_fixture(
                task, profile, bundle, Path(temporary) / "workspace"
            ) as handle:
                _write_state(handle, bundle.oracle.state)
                source = (
                    handle.workspace
                    / NESTED_JSON_SCHEMA_MIGRATION_INPUT
                )
                source.chmod(0o644)
                self.assertFalse(
                    verify_nested_json_schema_migration_workspace(
                        task, profile, bundle, handle
                    )
                )

    def test_workspace_rejects_hardlinks_and_symlink_target_mutation(
        self,
    ) -> None:
        task = TASK_BY_CELL[
            ("single-object", "rename-fields")
        ]
        profile = PROFILE_BY_ID["symlinks-ordering"]
        bundle = build_nested_json_schema_migration_fixture_bundle(
            task, profile
        )
        self.assertTrue(
            any(
                type(item) is InputSymlink
                for item in bundle.definition.inputs
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_nested_json_schema_migration_fixture(
                task, profile, bundle, Path(temporary) / "workspace"
            ) as handle:
                _write_state(handle, bundle.oracle.state)
                output = handle.workspace / "output/documents/000000.json"
                os.link(output, handle.workspace / "alias")
                self.assertFalse(
                    verify_nested_json_schema_migration_workspace(
                        task, profile, bundle, handle
                    )
                )

        with tempfile.TemporaryDirectory() as temporary:
            with materialize_nested_json_schema_migration_fixture(
                task, profile, bundle, Path(temporary) / "workspace"
            ) as handle:
                _write_state(handle, bundle.oracle.state)
                link = handle.workspace / "input/distractors/link"
                link.unlink()
                os.symlink("changed-target", link)
                self.assertFalse(
                    verify_nested_json_schema_migration_workspace(
                        task, profile, bundle, handle
                    )
                )


if __name__ == "__main__":
    unittest.main()
