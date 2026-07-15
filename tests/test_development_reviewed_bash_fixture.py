from __future__ import annotations

from dataclasses import fields, replace
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.development_invocation import (  # noqa: E402
    decode_development_invocation_frame,
    encode_development_invocation_frame,
    verify_development_invocation,
)
from cbds.development_reviewed_bash_fixture import (  # noqa: E402
    DEVELOPMENT_REVIEWED_BASH_FIXTURE_RECORD_TYPE,
    DEVELOPMENT_REVIEWED_BASH_FIXTURE_REVIEW_SCOPE,
    DevelopmentReviewedBashFixtureCase,
    DevelopmentReviewedBashFixtureError,
    FROZEN_FIRST_ADMISSION_SHA256,
    FROZEN_FIRST_CATALOG_SHA256,
    FROZEN_FIRST_REGISTRY_SHA256,
    FROZEN_FIRST_SUITE_SHA256,
    FROZEN_REVIEWED_BASH_PROGRAM,
    FROZEN_REVIEWED_BASH_RESPONSE,
    FROZEN_REVIEWED_CASE_SHA256,
    FROZEN_REVIEWED_EXTERNAL_COMMANDS,
    FROZEN_REVIEWED_FIXTURE_DEFINITION_SHA256,
    FROZEN_REVIEWED_FIXTURE_ID,
    FROZEN_REVIEWED_FIXTURE_SHA256,
    FROZEN_REVIEWED_GRAPH_SHA256,
    FROZEN_REVIEWED_INVOCATION_SHA256,
    FROZEN_REVIEWED_ORACLE_SHA256,
    FROZEN_REVIEWED_PROFILE_ID,
    FROZEN_REVIEWED_PROFILE_SHA256,
    FROZEN_REVIEWED_PROGRAM_SHA256,
    FROZEN_REVIEWED_RESPONSE_SHA256,
    FROZEN_REVIEWED_TASK_ID,
    FROZEN_REVIEWED_TASK_SHA256,
    FROZEN_REVIEWED_VERIFIER_IDENTITY,
    build_development_reviewed_bash_fixture_case,
    materialize_development_reviewed_bash_fixture,
    validate_development_reviewed_bash_fixture_case,
    verify_development_reviewed_bash_fixture_case,
)
from cbds.executable_fixture_verifier import (  # noqa: E402
    verify_executable_fixture,
)
from cbds.executable_static_types import PathSuffixInventoryParameters  # noqa: E402
from cbds.executable_workspace import InputFile  # noqa: E402


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _write_known_oracle_output(
    case: DevelopmentReviewedBashFixtureCase,
    workspace: Path,
) -> None:
    output = case.bundle.oracle.outputs[0]
    target = workspace / output.path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.parent.chmod(0o755)
    target.write_bytes(output.content)
    target.chmod(output.mode)


def _raw_case(
    original: DevelopmentReviewedBashFixtureCase,
    **changes: object,
) -> DevelopmentReviewedBashFixtureCase:
    forged = object.__new__(DevelopmentReviewedBashFixtureCase)
    for specification in fields(DevelopmentReviewedBashFixtureCase):
        value = changes.get(specification.name, getattr(original, specification.name))
        object.__setattr__(forged, specification.name, value)
    return forged


class DevelopmentReviewedBashFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.case = build_development_reviewed_bash_fixture_case()

    def test_exact_catalog_task_profile_fixture_and_authority_selection(self) -> None:
        case = self.case
        validate_development_reviewed_bash_fixture_case(case)
        self.assertTrue(verify_development_reviewed_bash_fixture_case(case))
        self.assertEqual(case.catalog.catalog_sha256, FROZEN_FIRST_CATALOG_SHA256)
        self.assertEqual(
            case.catalog.source_registry.registry_sha256,
            FROZEN_FIRST_REGISTRY_SHA256,
        )
        self.assertEqual(
            case.catalog.source_registry.suite_sha256,
            FROZEN_FIRST_SUITE_SHA256,
        )
        self.assertEqual(
            case.catalog_admission.admission_sha256,
            FROZEN_FIRST_ADMISSION_SHA256,
        )
        self.assertEqual(case.task.task_id, FROZEN_REVIEWED_TASK_ID)
        self.assertEqual(
            case.task.task_contract_sha256,
            FROZEN_REVIEWED_TASK_SHA256,
        )
        self.assertEqual(case.task.graph_sha256, FROZEN_REVIEWED_GRAPH_SHA256)
        self.assertIs(type(case.task.parameters), PathSuffixInventoryParameters)
        self.assertEqual(case.task.parameters.suffix, ".txt")
        self.assertEqual(case.task.parameters.maximum_depth, "unbounded")
        self.assertEqual(case.task.family_id, "path-suffix-inventory")
        self.assertEqual(case.task.allowed_tools, ("find", "mkdir", "sort"))
        self.assertEqual(case.profile.profile_id, FROZEN_REVIEWED_PROFILE_ID)
        self.assertEqual(
            case.profile.profile_sha256,
            FROZEN_REVIEWED_PROFILE_SHA256,
        )
        self.assertEqual(case.bundle.descriptor.fixture_id, FROZEN_REVIEWED_FIXTURE_ID)
        self.assertEqual(
            case.bundle.descriptor.fixture_sha256,
            FROZEN_REVIEWED_FIXTURE_SHA256,
        )
        self.assertEqual(
            case.bundle.fixture_definition_sha256,
            FROZEN_REVIEWED_FIXTURE_DEFINITION_SHA256,
        )
        self.assertEqual(case.bundle.oracle.oracle_sha256, FROZEN_REVIEWED_ORACLE_SHA256)
        self.assertEqual(
            case.bundle.oracle.semantic_verifier_identity,
            FROZEN_REVIEWED_VERIFIER_IDENTITY,
        )
        self.assertEqual(case.case_sha256, FROZEN_REVIEWED_CASE_SHA256)
        self.assertEqual(
            case.reviewed_external_commands,
            FROZEN_REVIEWED_EXTERNAL_COMMANDS,
        )
        for owner in (
            case,
            case.catalog,
            case.task,
            case.profile,
            case.bundle,
            case.invocation,
        ):
            for name in (
                "candidate_execution_authorized",
                "model_selection_eligible",
                "claim_authorized",
            ):
                if hasattr(owner, name):
                    self.assertIs(getattr(owner, name), False)
        for name in (
            "candidate_executed",
            "scored_evaluation_eligible",
            "claim_pipeline_eligible",
        ):
            self.assertIs(getattr(case, name), False)
            self.assertIs(getattr(case.invocation, name), False)

    def test_frozen_response_parser_and_invocation_are_exactly_bound(self) -> None:
        case = self.case
        self.assertTrue(verify_development_invocation(case.invocation))
        self.assertEqual(case.response, FROZEN_REVIEWED_BASH_RESPONSE.encode("utf-8"))
        self.assertEqual(case.program, FROZEN_REVIEWED_BASH_PROGRAM)
        self.assertTrue(case.invocation.fenced)
        self.assertEqual(
            sha256(case.response).hexdigest(),
            FROZEN_REVIEWED_RESPONSE_SHA256,
        )
        self.assertEqual(case.invocation.program_sha256, FROZEN_REVIEWED_PROGRAM_SHA256)
        self.assertEqual(
            case.invocation.invocation_sha256,
            FROZEN_REVIEWED_INVOCATION_SHA256,
        )
        self.assertNotIn(b"chmod", case.program)
        self.assertIn(b"umask 022", case.program)
        self.assertIn(b"mkdir -p -- output", case.program)
        self.assertIn(b"-perm /0444", case.program)
        frame = encode_development_invocation_frame(case.invocation)
        decoded = decode_development_invocation_frame(
            frame,
            catalog=case.catalog_admission,
        )
        self.assertEqual(decoded, case.invocation.to_protocol_record())

    def test_audit_projection_is_hash_only_and_content_addressed(self) -> None:
        audit = self.case.to_audit_record()
        self.assertEqual(
            audit["record_type"],
            DEVELOPMENT_REVIEWED_BASH_FIXTURE_RECORD_TYPE,
        )
        self.assertEqual(
            audit["review_scope"],
            DEVELOPMENT_REVIEWED_BASH_FIXTURE_REVIEW_SCOPE,
        )
        self.assertEqual(audit["case_sha256"], FROZEN_REVIEWED_CASE_SHA256)
        encoded = _canonical(audit)
        self.assertNotIn(FROZEN_REVIEWED_BASH_PROGRAM, encoded)
        self.assertNotIn(b"content_base64", encoded)
        self.assertNotIn(b"inputs", encoded)
        self.assertNotIn(b"outputs", encoded)
        self.assertNotIn(self.case.bundle.oracle.outputs[0].content, encoded)

    def test_materialization_and_known_output_pass_semantic_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            subprocess,
            "Popen",
            side_effect=AssertionError("candidate process started"),
        ), mock.patch.object(
            os,
            "system",
            side_effect=AssertionError("shell started"),
        ), mock.patch.object(
            os,
            "popen",
            side_effect=AssertionError("shell pipe started"),
        ):
            workspace = Path(temporary) / "workspace"
            with materialize_development_reviewed_bash_fixture(
                self.case,
                workspace,
            ) as handle:
                self.assertEqual(handle.scan_outputs().entries, ())
                _write_known_oracle_output(self.case, workspace)
                evidence = verify_executable_fixture(self.case.bundle, handle)
                self.assertTrue(evidence.passed)
                self.assertIsNone(evidence.failure_code)
                self.assertEqual(len(evidence.outputs), 1)
                self.assertEqual(
                    evidence.outputs[0].content_sha256,
                    sha256(self.case.bundle.oracle.outputs[0].content).hexdigest(),
                )

    def test_workspace_and_output_mutations_are_rejected(self) -> None:
        def output_bytes(workspace: Path) -> None:
            (workspace / "output/paths.txt").write_bytes(b"wrong.txt\n")

        def output_mode(workspace: Path) -> None:
            (workspace / "output/paths.txt").chmod(0o600)

        def extra_output(workspace: Path) -> None:
            (workspace / "output/extra.txt").write_bytes(b"extra")

        input_file = next(
            item
            for item in self.case.bundle.definition.inputs
            if type(item) is InputFile and item.mode & 0o200
        )

        def input_bytes(workspace: Path) -> None:
            target = workspace / input_file.path
            target.write_bytes(target.read_bytes() + b"changed")

        for name, mutation in (
            ("output-bytes", output_bytes),
            ("output-mode", output_mode),
            ("extra-output", extra_output),
            ("input-bytes", input_bytes),
        ):
            with self.subTest(mutation=name), tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary) / "workspace"
                with materialize_development_reviewed_bash_fixture(
                    self.case,
                    workspace,
                ) as handle:
                    _write_known_oracle_output(self.case, workspace)
                    mutation(workspace)
                    evidence = verify_executable_fixture(self.case.bundle, handle)
                    self.assertFalse(evidence.passed)
                    self.assertIsNotNone(evidence.failure_code)

    def test_forged_typed_values_and_nested_identity_substitution_fail_closed(self) -> None:
        self.assertFalse(verify_development_reviewed_bash_fixture_case(object()))
        with self.assertRaises(DevelopmentReviewedBashFixtureError):
            validate_development_reviewed_bash_fixture_case(object())  # type: ignore[arg-type]
        with self.assertRaises(DevelopmentReviewedBashFixtureError):
            replace(self.case, candidate_execution_authorized=True)
        with self.assertRaises(DevelopmentReviewedBashFixtureError):
            replace(self.case, case_sha256="0" * 64)
        with self.assertRaises(DevelopmentReviewedBashFixtureError):
            replace(self.case, reviewed_external_commands=("find", "curl"))

        copied_task = replace(self.case.task)
        copied_bundle = replace(self.case.bundle)
        for forged in (
            _raw_case(self.case, task=copied_task),
            _raw_case(self.case, bundle=copied_bundle),
            _raw_case(self.case, invocation=object()),
        ):
            with self.subTest(forged=type(forged)):
                self.assertFalse(verify_development_reviewed_bash_fixture_case(forged))
                with self.assertRaises(DevelopmentReviewedBashFixtureError):
                    validate_development_reviewed_bash_fixture_case(forged)

    def test_module_has_no_launch_path_and_build_is_safe_with_optimization(self) -> None:
        source = (
            ROOT / "src/cbds/development_reviewed_bash_fixture.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "subprocess",
            "os.system",
            "os.popen",
            "Popen",
            "assert ",
        ):
            self.assertNotIn(forbidden, source)

        opposite = ("-O",) if sys.flags.optimize == 0 else ()
        script = (
            "from cbds.development_reviewed_bash_fixture import "
            "build_development_reviewed_bash_fixture_case, "
            "verify_development_reviewed_bash_fixture_case, "
            "FROZEN_REVIEWED_CASE_SHA256; "
            "c=build_development_reviewed_bash_fixture_case(); "
            "raise SystemExit(0 if verify_development_reviewed_bash_fixture_case(c) "
            "and c.case_sha256 == FROZEN_REVIEWED_CASE_SHA256 else 7)"
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT / "src")
        completed = subprocess.run(
            [sys.executable, *opposite, "-c", script],
            cwd=ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=completed.stdout + completed.stderr,
        )


if __name__ == "__main__":
    unittest.main()
