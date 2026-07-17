from __future__ import annotations

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

from cbds.executable_checksum_repair_plan import (
    CHECKSUM_REPAIR_PLAN_ACTIONS,
    CHECKSUM_REPAIR_PLAN_ALLOWED_TOOLS,
    CHECKSUM_REPAIR_PLAN_ANCESTOR_SYMLINKS_COVERED,
    CHECKSUM_REPAIR_PLAN_ATOMICITY_OBSERVED,
    CHECKSUM_REPAIR_PLAN_CANDIDATE_EXIT_STATUS_OBSERVED,
    CHECKSUM_REPAIR_PLAN_DIRECTORY_PERMISSION_ERRORS_COVERED,
    CHECKSUM_REPAIR_PLAN_FAMILY_ID,
    CHECKSUM_REPAIR_PLAN_FINAL_PLAN_OBSERVED,
    CHECKSUM_REPAIR_PLAN_INPUT_PRESERVATION_OBSERVED,
    CHECKSUM_REPAIR_PLAN_MANIFEST,
    CHECKSUM_REPAIR_PLAN_MANIFEST_LAYOUTS,
    CHECKSUM_REPAIR_PLAN_OUTPUT,
    CHECKSUM_REPAIR_PLAN_OUTPUT_MAXIMUM_BYTES,
    CHECKSUM_REPAIR_PLAN_QUARANTINE_EXECUTION_OBSERVED,
    CHECKSUM_REPAIR_PLAN_READ_SCOPE_OBSERVED,
    CHECKSUM_REPAIR_PLAN_REPAIR_EXECUTION_OBSERVED,
    CHECKSUM_REPAIR_PLAN_REPAIR_POLICIES,
    CHECKSUM_REPAIR_PLAN_SPECIAL_FILE_KINDS_COVERED,
    CHECKSUM_REPAIR_PLAN_STATUSES,
    CHECKSUM_REPAIR_PLAN_STATES,
    CHECKSUM_REPAIR_PLAN_TOOL_HISTORY_OBSERVED,
    CHECKSUM_REPAIR_PLAN_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
    CHECKSUM_REPAIR_PLAN_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE,
    ChecksumRepairPlanError,
    ChecksumRepairPlanParameters,
    build_checksum_repair_plan_fixture_bundle,
    build_checksum_repair_plan_tasks,
    checksum_repair_plan_task_semantic_core,
    compute_checksum_repair_plan_discrimination_sha256,
    derive_checksum_repair_plan_state,
    materialize_checksum_repair_plan_fixture,
    parse_checksum_repair_plan_manifest,
    parse_checksum_repair_plan_output,
    reference_checksum_repair_plan_state,
    validate_checksum_repair_plan_fixture_bundle,
    validate_checksum_repair_plan_fixture_for_task_profile,
    verify_checksum_repair_plan_fixture_bundle,
    verify_checksum_repair_plan_fixture_for_task_profile,
    verify_checksum_repair_plan_workspace,
)
from cbds.executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_static_types import OpaqueFixtureDescriptor
from cbds.executable_workspace import (
    FixtureDefinition,
    InputFile,
    InputSymlink,
)


TASKS = build_checksum_repair_plan_tasks()
TASK_BY_CELL = {
    (task.parameters.manifest_layout, task.parameters.repair_policy): task
    for task in TASKS
}
PROFILE_BY_ID = {
    profile.profile_id: profile
    for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
}
EXPECTED_DISCRIMINATION_SHA256 = (
    "f71ba70f0a4d004bed235e897a73c1222c6d2687e4eeb842c008f7878e9457aa"
)


def _manifest_input(bundle: object) -> InputFile:
    matches = tuple(
        item
        for item in bundle.definition.inputs
        if type(item) is InputFile and item.path == CHECKSUM_REPAIR_PLAN_MANIFEST
    )
    if len(matches) != 1:
        raise AssertionError("test fixture does not have one manifest")
    return matches[0]


def _write_report(
    handle: object,
    payload: bytes,
    *,
    mode: int = 0o644,
) -> Path:
    output = handle.workspace / CHECKSUM_REPAIR_PLAN_OUTPUT
    output.parent.mkdir(parents=True, exist_ok=True)
    output.parent.chmod(0o755)
    output.write_bytes(payload)
    output.chmod(mode)
    return output


def _jsonl_objects(payload: bytes) -> list[dict[str, object]]:
    return [json.loads(line) for line in payload.decode("utf-8").splitlines()]


def _render_objects(values: list[dict[str, object]]) -> bytes:
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


class ChecksumRepairPlanTaskTests(unittest.TestCase):
    def test_grid_is_exact_unique_nonauthorizing_and_discriminable(self) -> None:
        expected = tuple(
            (layout, policy)
            for layout in CHECKSUM_REPAIR_PLAN_MANIFEST_LAYOUTS
            for policy in CHECKSUM_REPAIR_PLAN_REPAIR_POLICIES
        )
        self.assertEqual(len(TASKS), 20)
        self.assertEqual(
            tuple(
                (
                    task.parameters.manifest_layout,
                    task.parameters.repair_policy,
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
            compute_checksum_repair_plan_discrimination_sha256(TASKS),
            EXPECTED_DISCRIMINATION_SHA256,
        )
        for task in TASKS:
            with self.subTest(task=task.task_id):
                task.__post_init__()
                self.assertEqual(task.family_id, CHECKSUM_REPAIR_PLAN_FAMILY_ID)
                self.assertEqual(
                    task.allowed_tools, CHECKSUM_REPAIR_PLAN_ALLOWED_TOOLS
                )
                self.assertEqual(len(task.fixtures), 5)
                self.assertTrue(task.public)
                self.assertFalse(task.sealed)
                self.assertFalse(task.candidate_execution_authorized)
                self.assertFalse(task.model_selection_eligible)
                self.assertFalse(task.claim_authorized)
                semantic = checksum_repair_plan_task_semantic_core(
                    task.parameters, task.prompt, task.graph
                )
                self.assertEqual(
                    semantic["family_id"], CHECKSUM_REPAIR_PLAN_FAMILY_ID
                )
                self.assertEqual(
                    semantic["allowed_tools"],
                    list(CHECKSUM_REPAIR_PLAN_ALLOWED_TOOLS),
                )
                self.assertIn("declarative plan", task.prompt)
                self.assertIn("Retain record multiplicity", task.prompt)

    def test_parameter_task_and_graph_mutations_fail_closed(self) -> None:
        task = TASKS[0]
        with self.assertRaises(ChecksumRepairPlanError):
            ChecksumRepairPlanParameters("invented", "report-only")  # type: ignore[arg-type]
        with self.assertRaises(ChecksumRepairPlanError):
            ChecksumRepairPlanParameters("jsonl", "invented")  # type: ignore[arg-type]
        with self.assertRaises(ChecksumRepairPlanError):
            replace(task, prompt=task.prompt + " ")
        with self.assertRaises(ChecksumRepairPlanError):
            replace(task, candidate_execution_authorized=True)
        with self.assertRaises(ChecksumRepairPlanError):
            replace(task, allowed_tools=task.allowed_tools + ("cat",))
        with self.assertRaises(ChecksumRepairPlanError):
            replace(task, fixtures=(task.fixtures[0],) * len(task.fixtures))

    def test_observation_boundaries_are_explicit_and_narrow(self) -> None:
        self.assertTrue(CHECKSUM_REPAIR_PLAN_FINAL_PLAN_OBSERVED)
        self.assertTrue(CHECKSUM_REPAIR_PLAN_INPUT_PRESERVATION_OBSERVED)
        self.assertTrue(
            CHECKSUM_REPAIR_PLAN_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE
        )
        for value in (
            CHECKSUM_REPAIR_PLAN_REPAIR_EXECUTION_OBSERVED,
            CHECKSUM_REPAIR_PLAN_QUARANTINE_EXECUTION_OBSERVED,
            CHECKSUM_REPAIR_PLAN_ATOMICITY_OBSERVED,
            CHECKSUM_REPAIR_PLAN_TOOL_HISTORY_OBSERVED,
            CHECKSUM_REPAIR_PLAN_READ_SCOPE_OBSERVED,
            CHECKSUM_REPAIR_PLAN_CANDIDATE_EXIT_STATUS_OBSERVED,
            CHECKSUM_REPAIR_PLAN_DIRECTORY_PERMISSION_ERRORS_COVERED,
            CHECKSUM_REPAIR_PLAN_SPECIAL_FILE_KINDS_COVERED,
            CHECKSUM_REPAIR_PLAN_ANCESTOR_SYMLINKS_COVERED,
            CHECKSUM_REPAIR_PLAN_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
        ):
            self.assertFalse(value)


class ChecksumRepairPlanFixtureTests(unittest.TestCase):
    def test_all_100_bundles_reconstruct_and_cover_closed_semantics(self) -> None:
        statuses: set[str] = set()
        actions: set[str] = set()
        states: set[str] = set()
        fixture_ids: set[str] = set()
        count = 0
        for task in TASKS:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                with self.subTest(
                    layout=task.parameters.manifest_layout,
                    policy=task.parameters.repair_policy,
                    profile=profile.profile_id,
                ):
                    bundle = build_checksum_repair_plan_fixture_bundle(
                        task, profile
                    )
                    validate_checksum_repair_plan_fixture_bundle(bundle)
                    validate_checksum_repair_plan_fixture_for_task_profile(
                        task, profile, bundle
                    )
                    self.assertTrue(
                        verify_checksum_repair_plan_fixture_bundle(bundle)
                    )
                    self.assertTrue(
                        verify_checksum_repair_plan_fixture_for_task_profile(
                            task, profile, bundle
                        )
                    )
                    primary = derive_checksum_repair_plan_state(
                        bundle.definition, task.parameters
                    )
                    reference = reference_checksum_repair_plan_state(
                        bundle.definition, task.parameters
                    )
                    self.assertEqual(primary, reference)
                    self.assertEqual(primary, bundle.oracle.state)
                    self.assertEqual(
                        parse_checksum_repair_plan_output(primary.report),
                        primary.report,
                    )
                    manifest = _manifest_input(bundle)
                    records = parse_checksum_repair_plan_manifest(
                        manifest.content, task.parameters.manifest_layout
                    )
                    self.assertEqual(len(records), len(primary.entries))
                    statuses.update(entry.status for entry in primary.entries)
                    actions.update(entry.action for entry in primary.entries)
                    states.add(primary.state)
                    fixture_ids.add(bundle.descriptor.fixture_sha256)
                    count += 1
        self.assertEqual(count, 100)
        self.assertEqual(len(fixture_ids), 100)
        self.assertEqual(statuses, set(CHECKSUM_REPAIR_PLAN_STATUSES))
        self.assertEqual(actions, set(CHECKSUM_REPAIR_PLAN_ACTIONS))
        self.assertEqual(states, set(CHECKSUM_REPAIR_PLAN_STATES))

    def test_multiplicity_conflicting_digests_and_clean_strict_are_real(self) -> None:
        strict_task = TASK_BY_CELL[("jsonl", "strict-reject")]
        empty = build_checksum_repair_plan_fixture_bundle(
            strict_task, PROFILE_BY_ID["empty-duplicates"]
        )
        empty_entries = empty.oracle.state.entries
        self.assertEqual(empty.oracle.state.state, "clean")
        self.assertEqual(
            sum(entry.path == "empty.bin" for entry in empty_entries), 2
        )
        self.assertTrue(all(entry.action == "keep" for entry in empty_entries))

        replace_task = TASK_BY_CELL[("jsonl", "replace-digest")]
        spaces = build_checksum_repair_plan_fixture_bundle(
            replace_task, PROFILE_BY_ID["spaces-unicode"]
        )
        quoted = [
            entry
            for entry in spaces.oracle.state.entries
            if entry.path == 'quoted,"asset".bin'
        ]
        self.assertEqual(len(quoted), 2)
        self.assertEqual(
            {entry.status for entry in quoted}, {"ok", "checksum-mismatch"}
        )
        self.assertEqual(
            {entry.action for entry in quoted}, {"keep", "replace-digest"}
        )

    def test_physical_manifest_order_is_nonsemantic(self) -> None:
        task = TASK_BY_CELL[("jsonl", "report-only")]
        bundle = build_checksum_repair_plan_fixture_bundle(
            task, PROFILE_BY_ID["spaces-unicode"]
        )
        manifest = _manifest_input(bundle)
        lines = manifest.content.splitlines(keepends=True)
        self.assertGreater(len(lines), 2)
        inputs = tuple(
            replace(item, content=b"".join(reversed(lines)))
            if item is manifest
            else item
            for item in bundle.definition.inputs
        )
        reordered = FixtureDefinition(
            bundle.definition.fixture_id,
            inputs,
            bundle.definition.expected_files,
        )
        self.assertEqual(
            derive_checksum_repair_plan_state(reordered, task.parameters),
            bundle.oracle.state,
        )
        self.assertEqual(
            reference_checksum_repair_plan_state(
                reordered, task.parameters
            ),
            bundle.oracle.state,
        )

    def test_policy_action_and_state_table_is_exact(self) -> None:
        spaces = PROFILE_BY_ID["spaces-unicode"]
        expected_spaces = {
            "report-only": ("reported", {"report"}),
            "replace-digest": ("planned", {"keep", "replace-digest"}),
            "drop-missing": ("partial", {"keep", "unresolved"}),
            "quarantine-mismatch": (
                "planned",
                {"keep", "quarantine-asset"},
            ),
            "strict-reject": ("rejected", {"reject-batch"}),
        }
        for policy, (state, actions) in expected_spaces.items():
            with self.subTest(policy=policy):
                task = TASK_BY_CELL[("nul-pairs", policy)]
                plan = build_checksum_repair_plan_fixture_bundle(
                    task, spaces
                ).oracle.state
                self.assertEqual(plan.state, state)
                self.assertEqual(
                    {entry.action for entry in plan.entries}, actions
                )
        drop = build_checksum_repair_plan_fixture_bundle(
            TASK_BY_CELL[("jsonl", "drop-missing")],
            PROFILE_BY_ID["leading-dashes-globs"],
        ).oracle.state
        self.assertEqual(drop.state, "planned")
        self.assertEqual(
            [entry.action for entry in drop.entries].count("drop-record"), 1
        )

    def test_bundle_authority_descriptor_and_oracle_mutations_fail(self) -> None:
        task = TASKS[0]
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        bundle = build_checksum_repair_plan_fixture_bundle(task, profile)
        with self.assertRaises(ChecksumRepairPlanError):
            replace(bundle, candidate_execution_authorized=True)
        with self.assertRaises(ChecksumRepairPlanError):
            replace(bundle, fixture_definition_sha256="0" * 64)
        with self.assertRaises(ChecksumRepairPlanError):
            replace(
                bundle,
                descriptor=OpaqueFixtureDescriptor(
                    "fx-" + "0" * 24,
                    "0" * 64,
                    bundle.task_contract_sha256,
                ),
            )
        self.assertFalse(verify_checksum_repair_plan_fixture_bundle(object()))


class ChecksumRepairManifestParserTests(unittest.TestCase):
    DIGEST = "a" * 64
    OTHER = "b" * 64

    def test_valid_wire_formats_retain_multiplicity_and_conflicts(self) -> None:
        logical = (
            ("path one", self.DIGEST),
            ("path one", self.DIGEST),
            ("path one", self.OTHER),
        )
        payloads = {
            "sha256sum-text": (
                f"{self.DIGEST}  path one\n"
                f"{self.DIGEST}  path one\n"
                f"{self.OTHER}  path one\n"
            ).encode(),
            "jsonl": (
                f'{{"path":"path one","sha256":"{self.DIGEST}"}}\n'
                f'{{"sha256":"{self.DIGEST}","path":"path one"}}\n'
                f'{{"path":"path one","sha256":"{self.OTHER}"}}\n'
            ).encode(),
            "csv": (
                "path,sha256\r\n"
                f"path one,{self.DIGEST}\r\n"
                f"path one,{self.DIGEST}\r\n"
                f"path one,{self.OTHER}\r\n"
            ).encode(),
            "nul-pairs": (
                b"path one\0"
                + self.DIGEST.encode()
                + b"\0path one\0"
                + self.DIGEST.encode()
                + b"\0path one\0"
                + self.OTHER.encode()
                + b"\0"
            ),
        }
        for layout, payload in payloads.items():
            with self.subTest(layout=layout):
                self.assertEqual(
                    parse_checksum_repair_plan_manifest(
                        payload, layout  # type: ignore[arg-type]
                    ),
                    logical,
                )

    def test_all_manifest_grammars_fail_closed_on_adversarial_framing(self) -> None:
        d = self.DIGEST
        invalid = {
            "sha256sum-text": (
                f"{d}  ok".encode(),
                f"{d} ok\n".encode(),
                f"{d.upper()}  ok\n".encode(),
                f"{d}  ok\r\n".encode(),
                f"{d}  ../escape\n".encode(),
                f"{d}  .\n".encode(),
                f"{d}  bad\\\\path\n".encode(),
                f"{d}  ok\n\n".encode(),
                b"\xff" + f"{d[1:]}  ok\n".encode(),
            ),
            "jsonl": (
                f'{{"path":"ok","sha256":"{d}"}}'.encode(),
                f'{{"path":"ok","path":"ok","sha256":"{d}"}}\n'.encode(),
                f'{{"path":"ok","sha256":"{d}","x":1}}\n'.encode(),
                f'["ok","{d}"]\n'.encode(),
                f'{{"path":"../x","sha256":"{d}"}}\n'.encode(),
                f'{{"path":".","sha256":"{d}"}}\n'.encode(),
                f'{{"path":"ok","sha256":"{d}"}}\r\n'.encode(),
                b"\xff\n",
            ),
            "csv": (
                f"path,sha256\nok,{d}\n".encode(),
                f"sha256,path\r\n{d},ok\r\n".encode(),
                b"path,sha256\r\n",
                f"path,sha256\r\nok\r\n".encode(),
                f'path,sha256\r\n"unterminated,{d}\r\n'.encode(),
                f"path,sha256\r\n../x,{d}\r\n".encode(),
                f"path,sha256\r\n.,{d}\r\n".encode(),
                b"\xef\xbb\xbfpath,sha256\r\nok," + d.encode() + b"\r\n",
            ),
            "nul-pairs": (
                b"ok\0" + d.encode(),
                b"ok\0" + d.encode() + b"\0extra\0",
                b"\0" + d.encode() + b"\0",
                b"../x\0" + d.encode() + b"\0",
                b".\0" + d.encode() + b"\0",
                b"bad\\path\0" + d.encode() + b"\0",
                b"ok\0" + d.upper().encode() + b"\0",
                b"\xff\0" + d.encode() + b"\0",
            ),
        }
        for layout, payloads in invalid.items():
            for payload in payloads:
                with self.subTest(layout=layout, payload=payload[:30]):
                    with self.assertRaises(ChecksumRepairPlanError):
                        parse_checksum_repair_plan_manifest(
                            payload, layout  # type: ignore[arg-type]
                        )

    def test_manifest_bounds_and_invalid_layout_fail(self) -> None:
        with self.assertRaises(ChecksumRepairPlanError):
            parse_checksum_repair_plan_manifest(b"", "jsonl")
        with self.assertRaises(ChecksumRepairPlanError):
            parse_checksum_repair_plan_manifest(
                b"x" * (64 * 1024 + 1), "jsonl"
            )
        with self.assertRaises(ChecksumRepairPlanError):
            parse_checksum_repair_plan_manifest(
                b"irrelevant", "unknown"  # type: ignore[arg-type]
            )

    def test_csv_header_counts_toward_128_physical_record_bound(self) -> None:
        header = b"path,sha256\r\n"
        row = b"same-path," + self.DIGEST.encode() + b"\r\n"
        accepted = header + row * 127
        rejected = header + row * 128
        self.assertEqual(
            len(parse_checksum_repair_plan_manifest(accepted, "csv")), 127
        )
        with self.assertRaises(ChecksumRepairPlanError):
            parse_checksum_repair_plan_manifest(rejected, "csv")


class ChecksumRepairOutputParserTests(unittest.TestCase):
    def setUp(self) -> None:
        task = TASK_BY_CELL[("csv", "replace-digest")]
        self.bundle = build_checksum_repair_plan_fixture_bundle(
            task, PROFILE_BY_ID["spaces-unicode"]
        )
        self.oracle = self.bundle.oracle.state.report

    def test_key_order_and_insignificant_whitespace_are_semantic(self) -> None:
        values = _jsonl_objects(self.oracle)
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
        self.assertNotEqual(varied, self.oracle)
        self.assertEqual(
            parse_checksum_repair_plan_output(varied), self.oracle
        )

    def test_output_rejects_schema_count_order_status_action_and_framing_mutants(
        self,
    ) -> None:
        base = _jsonl_objects(self.oracle)
        mutants: list[bytes] = [
            self.oracle[:-1],
            self.oracle.replace(b"\n", b"\r\n", 1),
            b"\n" + self.oracle,
            self.oracle + b"\n",
            b"\xff\n",
            b"[" * 100_000
            + b"0"
            + b"]" * 100_000
            + b"\n{}\n",
            b'{"record":"plan","policy":"replace-digest","state":"planned",'
            b'"entry_count":'
            + b"1" * 5_000
            + b',"issue_count":0,"action_count":0,"unresolved_count":0}\n{}\n',
        ]
        changed = [dict(value) for value in base]
        changed[0]["extra"] = 1
        mutants.append(_render_objects(changed))
        changed = [dict(value) for value in base]
        changed[0]["entry_count"] = int(changed[0]["entry_count"]) + 1
        mutants.append(_render_objects(changed))
        changed = [dict(value) for value in base]
        changed[1]["status"] = "invented"
        mutants.append(_render_objects(changed))
        changed = [dict(value) for value in base]
        changed[1]["action"] = "drop-record"
        mutants.append(_render_objects(changed))
        changed = [dict(value) for value in base]
        changed[1]["actual_sha256"] = None
        mutants.append(_render_objects(changed))
        changed = [dict(value) for value in base]
        changed[1]["path"] = "."
        mutants.append(_render_objects(changed))
        changed = [dict(value) for value in base]
        changed[1], changed[2] = changed[2], changed[1]
        mutants.append(_render_objects(changed))
        duplicate_header = (
            self.oracle.splitlines()[0]
            .replace(b'"record":"plan"', b'"record":"plan","record":"plan"')
            + b"\n"
            + b"\n".join(self.oracle.splitlines()[1:])
            + b"\n"
        )
        mutants.append(duplicate_header)
        for mutant in mutants:
            with self.subTest(mutant=mutant[:80]):
                with self.assertRaises(ChecksumRepairPlanError):
                    parse_checksum_repair_plan_output(mutant)

    def test_output_bound_is_enforced(self) -> None:
        with self.assertRaises(ChecksumRepairPlanError):
            parse_checksum_repair_plan_output(
                b"x" * (CHECKSUM_REPAIR_PLAN_OUTPUT_MAXIMUM_BYTES + 1)
            )

    def test_duplicate_rows_must_agree_on_one_observed_asset_state(self) -> None:
        task = TASK_BY_CELL[("jsonl", "report-only")]
        bundle = build_checksum_repair_plan_fixture_bundle(
            task, PROFILE_BY_ID["empty-duplicates"]
        )
        values = _jsonl_objects(bundle.oracle.state.report)
        indices = [
            index
            for index, value in enumerate(values)
            if value.get("path") == "empty.bin"
        ]
        self.assertEqual(len(indices), 2)
        changed = [dict(value) for value in values]
        row = changed[indices[1]]
        row["status"] = "checksum-mismatch"
        row["actual_sha256"] = "f" * 64
        changed[0]["issue_count"] = 1
        changed[0]["state"] = "reported"
        with self.assertRaises(ChecksumRepairPlanError):
            parse_checksum_repair_plan_output(_render_objects(changed))


class ChecksumRepairDefinitionMutationTests(unittest.TestCase):
    def test_asset_byte_mutation_changes_classification_in_both_engines(
        self,
    ) -> None:
        task = TASK_BY_CELL[("jsonl", "report-only")]
        bundle = build_checksum_repair_plan_fixture_bundle(
            task, PROFILE_BY_ID["empty-duplicates"]
        )
        inputs = list(bundle.definition.inputs)
        index = next(
            index
            for index, item in enumerate(inputs)
            if type(item) is InputFile
            and item.path == "input/assets/duplicates/one.bin"
        )
        original = inputs[index]
        if type(original) is not InputFile:
            self.fail("selected asset is not an exact InputFile")
        inputs[index] = replace(original, content=original.content + b"!")
        mutated = FixtureDefinition(
            bundle.definition.fixture_id,
            tuple(inputs),
            bundle.definition.expected_files,
        )
        primary = derive_checksum_repair_plan_state(mutated, task.parameters)
        reference = reference_checksum_repair_plan_state(
            mutated, task.parameters
        )
        self.assertEqual(primary, reference)
        self.assertEqual(
            next(
                entry.status
                for entry in primary.entries
                if entry.path == "duplicates/one.bin"
            ),
            "checksum-mismatch",
        )
        self.assertNotEqual(primary, bundle.oracle.state)

    def test_malformed_manifest_and_symlink_ancestor_fail_closed(self) -> None:
        task = TASK_BY_CELL[("sha256sum-text", "report-only")]
        bundle = build_checksum_repair_plan_fixture_bundle(
            task, PROFILE_BY_ID["leading-dashes-globs"]
        )
        inputs = list(bundle.definition.inputs)
        manifest_index = next(
            index
            for index, item in enumerate(inputs)
            if type(item) is InputFile
            and item.path == CHECKSUM_REPAIR_PLAN_MANIFEST
        )
        manifest = inputs[manifest_index]
        if type(manifest) is not InputFile:
            self.fail("selected manifest is not an exact InputFile")
        inputs[manifest_index] = replace(
            manifest, content=manifest.content[:-1]
        )
        malformed = FixtureDefinition(
            bundle.definition.fixture_id,
            tuple(inputs),
            bundle.definition.expected_files,
        )
        with self.assertRaises(ChecksumRepairPlanError):
            derive_checksum_repair_plan_state(malformed, task.parameters)
        with self.assertRaises(ChecksumRepairPlanError):
            reference_checksum_repair_plan_state(
                malformed, task.parameters
            )

        digest = sha256(b"missing below link").hexdigest()
        ancestor_manifest = InputFile(
            CHECKSUM_REPAIR_PLAN_MANIFEST,
            f"{digest}  link/child\n".encode(),
            0o600,
        )
        ancestor = FixtureDefinition(
            "fixture.checksum.ancestor-link",
            (
                ancestor_manifest,
                InputSymlink("input/assets/link", "target"),
            ),
            (),
        )
        with self.assertRaises(ChecksumRepairPlanError):
            derive_checksum_repair_plan_state(ancestor, task.parameters)
        with self.assertRaises(ChecksumRepairPlanError):
            reference_checksum_repair_plan_state(
                ancestor, task.parameters
            )


class ChecksumRepairWorkspaceTests(unittest.TestCase):
    def test_all_100_oracle_final_states_pass_complete_workspace_verifier(
        self,
    ) -> None:
        for task in TASKS:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                with self.subTest(
                    layout=task.parameters.manifest_layout,
                    policy=task.parameters.repair_policy,
                    profile=profile.profile_id,
                ), tempfile.TemporaryDirectory() as temporary:
                    bundle = build_checksum_repair_plan_fixture_bundle(
                        task, profile
                    )
                    with materialize_checksum_repair_plan_fixture(
                        task,
                        profile,
                        bundle,
                        Path(temporary) / "workspace",
                    ) as handle:
                        _write_report(handle, bundle.oracle.state.report)
                        self.assertTrue(
                            verify_checksum_repair_plan_workspace(
                                task, profile, bundle, handle
                            )
                        )

    def test_workspace_accepts_semantically_equivalent_json(self) -> None:
        task = TASK_BY_CELL[("csv", "quarantine-mismatch")]
        profile = PROFILE_BY_ID["spaces-unicode"]
        bundle = build_checksum_repair_plan_fixture_bundle(task, profile)
        values = _jsonl_objects(bundle.oracle.state.report)
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
            with materialize_checksum_repair_plan_fixture(
                task,
                profile,
                bundle,
                Path(temporary) / "workspace",
            ) as handle:
                _write_report(handle, varied)
                self.assertTrue(
                    verify_checksum_repair_plan_workspace(
                        task, profile, bundle, handle
                    )
                )

    def test_workspace_rejects_report_input_metadata_and_topology_mutations(
        self,
    ) -> None:
        task = TASK_BY_CELL[("jsonl", "replace-digest")]
        profile = PROFILE_BY_ID["spaces-unicode"]
        bundle = build_checksum_repair_plan_fixture_bundle(task, profile)

        def run_mutant(mutator: object) -> None:
            with tempfile.TemporaryDirectory() as temporary:
                with materialize_checksum_repair_plan_fixture(
                    task,
                    profile,
                    bundle,
                    Path(temporary) / "workspace",
                ) as handle:
                    report = _write_report(
                        handle, bundle.oracle.state.report
                    )
                    mutator(handle, report)
                    self.assertFalse(
                        verify_checksum_repair_plan_workspace(
                            task, profile, bundle, handle
                        )
                    )

        def corrupt_report(_handle: object, report: Path) -> None:
            report.write_bytes(report.read_bytes().replace(b'"planned"', b'"partial"', 1))

        def deeply_nested_report(_handle: object, report: Path) -> None:
            report.write_bytes(
                b"[" * 100_000
                + b"0"
                + b"]" * 100_000
                + b"\n{}\n"
            )

        def wrong_report_mode(_handle: object, report: Path) -> None:
            report.chmod(0o600)

        def report_symlink(handle: object, report: Path) -> None:
            report.unlink()
            report.symlink_to("../missing-report")

        def extra_output(handle: object, _report: Path) -> None:
            extra = handle.workspace / "output" / "extra"
            extra.write_bytes(b"extra\n")

        def mutate_input(handle: object, _report: Path) -> None:
            source = (
                handle.workspace
                / "input"
                / "assets"
                / "space dir"
                / "café 雪.txt"
            )
            source.write_bytes(b"mutated\n")
            source.chmod(0o640)

        def mutate_input_mode(handle: object, _report: Path) -> None:
            source = (
                handle.workspace
                / "input"
                / "assets"
                / "space dir"
                / "café 雪.txt"
            )
            source.chmod(0o600)

        def mutate_input_mtime(handle: object, _report: Path) -> None:
            source = (
                handle.workspace
                / "input"
                / "assets"
                / "space dir"
                / "café 雪.txt"
            )
            os.utime(source, (2_000, 2_000))

        def remove_input(handle: object, _report: Path) -> None:
            source = (
                handle.workspace
                / "input"
                / "assets"
                / "space dir"
                / "café 雪.txt"
            )
            source.unlink()

        def add_input_hardlink(handle: object, _report: Path) -> None:
            source = (
                handle.workspace
                / "input"
                / "assets"
                / "space dir"
                / "café 雪.txt"
            )
            os.link(source, handle.workspace / "input" / "extra-hardlink")

        def mutate_symlink_target(handle: object, _report: Path) -> None:
            link = handle.workspace / "input" / "outside" / "not-present"
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to("invented")

        def external_hardlink(handle: object, report: Path) -> None:
            os.link(report, handle.workspace / "external-hardlink")

        for name, mutator in (
            ("report", corrupt_report),
            ("deep-report", deeply_nested_report),
            ("mode", wrong_report_mode),
            ("symlink", report_symlink),
            ("extra", extra_output),
            ("input-bytes", mutate_input),
            ("input-mode", mutate_input_mode),
            ("input-mtime", mutate_input_mtime),
            ("input-removal", remove_input),
            ("input-hardlink", add_input_hardlink),
            ("extra-input-link", mutate_symlink_target),
            ("hardlink", external_hardlink),
        ):
            with self.subTest(name=name):
                run_mutant(mutator)

    def test_workspace_rejects_existing_input_symlink_target_mutation(
        self,
    ) -> None:
        task = TASK_BY_CELL[("jsonl", "report-only")]
        profile = PROFILE_BY_ID["leading-dashes-globs"]
        bundle = build_checksum_repair_plan_fixture_bundle(task, profile)
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_checksum_repair_plan_fixture(
                task,
                profile,
                bundle,
                Path(temporary) / "workspace",
            ) as handle:
                _write_report(handle, bundle.oracle.state.report)
                link = (
                    handle.workspace
                    / "input"
                    / "assets"
                    / "-unlisted[*]?"
                )
                link.unlink()
                link.symlink_to("literal?/star*.dat")
                self.assertFalse(
                    verify_checksum_repair_plan_workspace(
                        task, profile, bundle, handle
                    )
                )


if __name__ == "__main__":
    unittest.main()
