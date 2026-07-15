from __future__ import annotations

from dataclasses import replace
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

from cbds.executable_fixture_bundle import (  # noqa: E402
    ExecutableFixtureBundle,
    OracleOutputRecord,
    build_executable_fixture_bundle,
    build_trusted_fixture_oracle,
)
from cbds.executable_fixture_verifier import (  # noqa: E402
    ExecutableFixtureVerificationError,
    FixtureVerificationEvidence,
    is_fixture_verification_evidence_bound,
    is_structurally_valid_fixture_verification_evidence,
    validate_fixture_verification_evidence_binding,
    validate_fixture_verification_evidence_structure,
    verify_executable_fixture,
)
from cbds.executable_workspace import (  # noqa: E402
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    WorkspaceHandle,
    WorkspaceOutputReadError,
    materialize_fixture,
)
from cbds.executable_static_types import domain_sha256  # noqa: E402


TASK_SHA256 = "6" * 64
PROFILE_SHA256 = "7" * 64


def make_bundle(
    verifier: str,
    oracle_payloads: dict[str, bytes],
    *,
    fixture_id: str = "fixture.semantic-verifier",
    expected_modes: dict[str, int | None] | None = None,
    oracle_modes: dict[str, int] | None = None,
    input_content: bytes = b"immutable-input\n",
) -> ExecutableFixtureBundle:
    selected_expected_modes = {} if expected_modes is None else expected_modes
    selected_oracle_modes = {} if oracle_modes is None else oracle_modes
    paths = sorted(oracle_payloads, key=str.encode)
    definition = FixtureDefinition(
        fixture_id=fixture_id,
        inputs=(InputFile("input/source.txt", input_content, 0o640),),
        expected_files=tuple(
            ExpectedFile(
                path,
                maximum_bytes=max(256, len(oracle_payloads[path]) * 4),
                mode=selected_expected_modes.get(path, 0o644),
            )
            for path in paths
        ),
    )
    oracle = build_trusted_fixture_oracle(
        tuple(
            OracleOutputRecord(
                path,
                oracle_payloads[path],
                selected_oracle_modes.get(path, 0o644),
            )
            for path in paths
        ),
        semantic_verifier_identity=verifier,  # type: ignore[arg-type]
    )
    return build_executable_fixture_bundle(
        task_contract_sha256=TASK_SHA256,
        profile_sha256=PROFILE_SHA256,
        definition=definition,
        oracle=oracle,
    )


def write_outputs(
    handle: WorkspaceHandle,
    bundle: ExecutableFixtureBundle,
    *,
    payloads: dict[str, bytes] | None = None,
    modes: dict[str, int] | None = None,
) -> None:
    selected_payloads = {} if payloads is None else payloads
    selected_modes = {} if modes is None else modes
    for oracle in bundle.oracle.outputs:
        target = handle.workspace / oracle.path
        target.parent.mkdir(parents=True, exist_ok=True)
        relative_parent = target.parent.relative_to(handle.workspace)
        current = handle.workspace
        for component in relative_parent.parts:
            current /= component
            current.chmod(0o755)
        target.write_bytes(selected_payloads.get(oracle.path, oracle.content))
        target.chmod(selected_modes.get(oracle.path, oracle.mode))


class ExactSemanticDispatchTests(unittest.TestCase):
    def test_line_and_tree_verifiers_use_exact_bytes(self) -> None:
        cases = (
            (
                "verify-active-jsonl-labels-v1",
                {"output/labels.txt": b"alpha\nbeta\n"},
            ),
            (
                "verify-path-suffix-inventory-v1",
                {"output/paths.txt": b"a.txt\nnested/b.txt\n"},
            ),
            (
                "verify-manifest-copy-tree-v1",
                {
                    "output/a.txt": b"first\n",
                    "output/nested/b.bin": b"\x00\x01\xff",
                },
            ),
            (
                "verify-line-transform-mirror-v1",
                {
                    "output/mirror/a.txt": b"A\tB\r\n\xff",
                    "output/mirror/nested/empty.txt": b"",
                },
            ),
            (
                "verify-mode-normalized-mirror-v1",
                {"output/mirror/tool": b"#!/bin/sh\n"},
            ),
            (
                "verify-ustar-safe-extract-v1",
                {"output/extracted/nested/a.txt": b"archive bytes\n"},
            ),
        )
        for verifier, payloads in cases:
            with self.subTest(
                verifier=verifier
            ), tempfile.TemporaryDirectory() as temporary:
                bundle = make_bundle(verifier, payloads)
                with materialize_fixture(
                    bundle.definition, Path(temporary) / "workspace"
                ) as handle:
                    write_outputs(handle, bundle)
                    evidence = verify_executable_fixture(bundle, handle)
                    self.assertTrue(evidence.passed)
                    self.assertIsNone(evidence.failure_code)
                    self.assertEqual(len(evidence.outputs), len(payloads))

                    first = bundle.oracle.outputs[0]
                    changed = dict(payloads)
                    changed[first.path] = first.content + (
                        b"zz-changed\n"
                        if verifier
                        in {
                            "verify-active-jsonl-labels-v1",
                            "verify-path-suffix-inventory-v1",
                        }
                        else b"changed"
                    )
                    write_outputs(handle, bundle, payloads=changed)
                    failure = verify_executable_fixture(bundle, handle)
                    self.assertFalse(failure.passed)
                    self.assertEqual(failure.failure_code, "semantic-mismatch")

    def test_line_verifiers_reject_malformed_actual_and_trusted_oracle_bytes(self) -> None:
        cases = (
            (
                "verify-active-jsonl-labels-v1",
                "output/labels.txt",
                b"alpha\nbeta\n",
                b"beta\nalpha\n",
            ),
            (
                "verify-path-suffix-inventory-v1",
                "output/paths.txt",
                b"a.txt\nnested/b.txt\n",
                b"../escape.txt\n",
            ),
        )
        for verifier, path, oracle, malformed in cases:
            with self.subTest(verifier=verifier), tempfile.TemporaryDirectory() as temporary:
                bundle = make_bundle(verifier, {path: oracle})
                with materialize_fixture(
                    bundle.definition, Path(temporary) / "workspace"
                ) as handle:
                    write_outputs(handle, bundle, payloads={path: malformed})
                    evidence = verify_executable_fixture(bundle, handle)
                    self.assertEqual(
                        evidence.failure_code, "malformed-semantic-output"
                    )
            with self.subTest(
                verifier=verifier, oracle="invalid"
            ), tempfile.TemporaryDirectory() as temporary:
                bad_oracle = make_bundle(verifier, {path: malformed})
                with materialize_fixture(
                    bad_oracle.definition, Path(temporary) / "workspace"
                ) as handle:
                    write_outputs(handle, bad_oracle)
                    evidence = verify_executable_fixture(bad_oracle, handle)
                    self.assertEqual(
                        evidence.failure_code, "trusted-oracle-invalid"
                    )

    def test_every_declared_output_uses_safe_workspace_egress(self) -> None:
        bundle = make_bundle(
            "verify-manifest-copy-tree-v1",
            {"one": b"1", "tree/two": b"2", "tree/three": b"3"},
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(
                bundle.definition, Path(temporary) / "workspace"
            ) as handle:
                write_outputs(handle, bundle)
                original = WorkspaceHandle.read_output_bytes
                paths: list[str] = []

                def tracked(
                    selected: WorkspaceHandle, scan: object, path: str
                ) -> bytes:
                    paths.append(path)
                    return original(selected, scan, path)  # type: ignore[arg-type]

                with mock.patch.object(
                    WorkspaceHandle, "read_output_bytes", new=tracked
                ):
                    evidence = verify_executable_fixture(bundle, handle)
                self.assertTrue(evidence.passed)
                self.assertEqual(
                    paths,
                    [output.path for output in bundle.oracle.outputs],
                )


class CsvSemanticTests(unittest.TestCase):
    ORACLE = b'category,total\nalpha,1\n"beta,group",2\n'

    def test_csv_compares_strict_semantic_records_not_quote_spelling(self) -> None:
        bundle = make_bundle(
            "verify-csv-group-totals-v1", {"output/totals.csv": self.ORACLE}
        )
        actual = b'category,total\n"alpha",1\n"beta,group",2\n'
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(
                bundle.definition, Path(temporary) / "workspace"
            ) as handle:
                write_outputs(
                    handle,
                    bundle,
                    payloads={"output/totals.csv": actual},
                )
                self.assertTrue(verify_executable_fixture(bundle, handle).passed)

    def test_csv_rejects_malformed_shape_framing_order_and_totals(self) -> None:
        malformed = (
            b"category,total\nalpha,1\n\xff\n",
            b"category,total\r\nalpha,1\r\n",
            b"wrong,total\nalpha,1\n",
            b"category,total\nbeta,1\nalpha,2\n",
            b"category,total\nalpha,1\nalpha,2\n",
            b"category,total\nalpha,01\n",
            b'category,total\nal"pha,1\n',
            b"category,total\nalpha,1",
            b"category,total\nalpha,1,extra\n",
            b'category,total\n"alpha"tail,1\n',
        )
        for payload in malformed:
            with self.subTest(
                payload=payload
            ), tempfile.TemporaryDirectory() as temporary:
                bundle = make_bundle(
                    "verify-csv-group-totals-v1",
                    {"output/totals.csv": self.ORACLE},
                )
                with materialize_fixture(
                    bundle.definition, Path(temporary) / "workspace"
                ) as handle:
                    write_outputs(
                        handle,
                        bundle,
                        payloads={"output/totals.csv": payload},
                    )
                    evidence = verify_executable_fixture(bundle, handle)
                    self.assertFalse(evidence.passed)
                    self.assertEqual(
                        evidence.failure_code, "malformed-semantic-output"
                    )

    def test_csv_distinguishes_valid_semantic_mismatch_and_bad_oracle(self) -> None:
        actual = b'category,total\nalpha,9\n"beta,group",2\n'
        bundle = make_bundle(
            "verify-csv-group-totals-v1", {"output/totals.csv": self.ORACLE}
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(
                bundle.definition, Path(temporary) / "workspace"
            ) as handle:
                write_outputs(
                    handle, bundle, payloads={"output/totals.csv": actual}
                )
                evidence = verify_executable_fixture(bundle, handle)
                self.assertEqual(evidence.failure_code, "semantic-mismatch")

        bad_oracle = make_bundle(
            "verify-csv-group-totals-v1",
            {"output/totals.csv": b"not,csv\n"},
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(
                bad_oracle.definition, Path(temporary) / "workspace"
            ) as handle:
                write_outputs(handle, bad_oracle)
                evidence = verify_executable_fixture(bad_oracle, handle)
                self.assertEqual(evidence.failure_code, "trusted-oracle-invalid")


class SecondTrancheJsonlSemanticTests(unittest.TestCase):
    JOIN = (
        b'{"key":"alpha","left":{"id":"alpha","v":1},'
        b'"right":{"id":"alpha","v":2}}\n'
        b'{"key":"beta","left":{"id":"beta"},'
        b'"right":{"id":"beta"}}\n'
    )
    PROC = (
        b'{"pid":2,"ppid":1,"state":"S"}\n'
        b'{"pid":10,"ppid":2,"state":"R"}\n'
    )

    def test_join_and_proc_canonical_jsonl_pass(self) -> None:
        cases = (
            (
                "verify-jsonl-keyed-inner-join-v1",
                "output/joined.jsonl",
                self.JOIN,
            ),
            (
                "verify-proc-snapshot-report-v1",
                "output/processes.jsonl",
                self.PROC,
            ),
        )
        for verifier, path, payload in cases:
            with self.subTest(verifier=verifier), tempfile.TemporaryDirectory() as temporary:
                bundle = make_bundle(verifier, {path: payload})
                with materialize_fixture(
                    bundle.definition, Path(temporary) / "workspace"
                ) as handle:
                    write_outputs(handle, bundle)
                    self.assertTrue(verify_executable_fixture(bundle, handle).passed)

    def test_join_rejects_invalid_shape_key_mismatch_and_order(self) -> None:
        malformed = (
            b'{"key":"a","left":{"id":"different"},"right":{"id":"a"}}\n',
            (
                b'{"key":"b","left":{"id":"b"},"right":{"id":"b"}}\n'
                b'{"key":"a","left":{"id":"a"},"right":{"id":"a"}}\n'
            ),
            b'{"key":"a","key":"a","left":{"id":"a"},"right":{"id":"a"}}\n',
            b'{"key":"a","left":{"id":"a","n":1.0},"right":{"id":"a"}}\n',
            b'{"key":"a","left":{"id":"a","n":9007199254740992},"right":{"id":"a"}}\n',
        )
        for payload in malformed:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as temporary:
                bundle = make_bundle(
                    "verify-jsonl-keyed-inner-join-v1",
                    {"output/joined.jsonl": self.JOIN},
                )
                with materialize_fixture(
                    bundle.definition, Path(temporary) / "workspace"
                ) as handle:
                    write_outputs(
                        handle,
                        bundle,
                        payloads={"output/joined.jsonl": payload},
                    )
                    evidence = verify_executable_fixture(bundle, handle)
                    self.assertEqual(
                        evidence.failure_code,
                        "malformed-semantic-output",
                    )

    def test_jsonl_semantics_accept_whitespace_key_order_and_escape_spelling(
        self,
    ) -> None:
        cases = (
            (
                "verify-jsonl-keyed-inner-join-v1",
                "output/joined.jsonl",
                self.JOIN,
                (
                    b'{ "right" : {"v":2,"id":"alpha"}, "left" : '
                    b'{"v":1,"id":"alpha"}, "key" : "\\u0061lpha" }\n'
                    b'{"right":{"id":"beta"},"left":{"id":"beta"},'
                    b'"key":"beta"}\n'
                ),
            ),
            (
                "verify-proc-snapshot-report-v1",
                "output/processes.jsonl",
                self.PROC,
                (
                    b'{ "state":"S", "ppid":1, "pid":2 }\n'
                    b'{"state":"R", "pid":10, "ppid":2}\n'
                ),
            ),
        )
        for verifier, path, oracle, actual in cases:
            with self.subTest(verifier=verifier), tempfile.TemporaryDirectory() as temporary:
                bundle = make_bundle(verifier, {path: oracle})
                with materialize_fixture(
                    bundle.definition, Path(temporary) / "workspace"
                ) as handle:
                    write_outputs(handle, bundle, payloads={path: actual})
                    self.assertTrue(verify_executable_fixture(bundle, handle).passed)

    def test_proc_rejects_mixed_shape_bad_pid_order_and_bad_argv(self) -> None:
        malformed = (
            b'{"pid":1,"ppid":0,"uid":0}\n',
            (
                b'{"pid":2,"uid":0}\n'
                b'{"pid":2,"uid":1}\n'
            ),
            b'{"argv":[""],"comm":"sh","pid":3}\n',
            b'{"pid":true,"uid":0}\n',
        )
        for payload in malformed:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as temporary:
                bundle = make_bundle(
                    "verify-proc-snapshot-report-v1",
                    {"output/processes.jsonl": self.PROC},
                )
                with materialize_fixture(
                    bundle.definition, Path(temporary) / "workspace"
                ) as handle:
                    write_outputs(
                        handle,
                        bundle,
                        payloads={"output/processes.jsonl": payload},
                    )
                    evidence = verify_executable_fixture(bundle, handle)
                    self.assertEqual(
                        evidence.failure_code,
                        "malformed-semantic-output",
                    )

    def test_jsonl_verifiers_fail_closed_on_excessive_nesting(self) -> None:
        oracle_value = {
            "key": "a",
            "left": {"id": "a", "padding": "x" * 2_000},
            "right": {"id": "a"},
        }
        oracle = (
            json.dumps(
                oracle_value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        nested = (
            b'{"key":"a","left":{"id":"a","nested":'
            + b"[" * 1_500
            + b"0"
            + b"]" * 1_500
            + b'},"right":{"id":"a"}}\n'
        )
        with tempfile.TemporaryDirectory() as temporary:
            bundle = make_bundle(
                "verify-jsonl-keyed-inner-join-v1",
                {"output/joined.jsonl": oracle},
            )
            with materialize_fixture(
                bundle.definition, Path(temporary) / "workspace"
            ) as handle:
                write_outputs(
                    handle,
                    bundle,
                    payloads={"output/joined.jsonl": nested},
                )
                evidence = verify_executable_fixture(bundle, handle)
                self.assertFalse(evidence.passed)
                self.assertIn(
                    evidence.failure_code,
                    {"malformed-semantic-output", "semantic-mismatch"},
                )

class ChecksumJsonlSemanticTests(unittest.TestCase):
    ORACLE = (
        b'{"path":"a","status":"ok"}\n'
        b'{"path":"b","status":"missing"}\n'
    )

    def test_checksum_jsonl_allows_key_order_and_whitespace_variation(self) -> None:
        actual = (
            b'{ "status" : "ok", "path" : "a" }\n'
            b'{"status":"missing", "path":"b"}\n'
        )
        bundle = make_bundle(
            "verify-checksum-manifest-v1", {"output/report.jsonl": self.ORACLE}
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(
                bundle.definition, Path(temporary) / "workspace"
            ) as handle:
                write_outputs(
                    handle,
                    bundle,
                    payloads={"output/report.jsonl": actual},
                )
                self.assertTrue(verify_executable_fixture(bundle, handle).passed)

    def test_checksum_jsonl_rejects_keys_types_order_duplicates_and_framing(
        self,
    ) -> None:
        malformed = (
            b'{"path":"a","status":"ok","extra":"x"}\n',
            b'{"path":"a","status":1}\n',
            b'{"path":"../a","status":"ok"}\n',
            b'{"path":"\\ud800","status":"ok"}\n',
            b'{"path":"a","status":"invented"}\n',
            (
                b'{"path":"b","status":"missing"}\n'
                b'{"path":"a","status":"ok"}\n'
            ),
            b'{"path":"a","path":"a","status":"ok"}\n',
            b'{bad json}\n',
            b'{"path":"a","status":"ok"}',
            b'\n',
        )
        for payload in malformed:
            with self.subTest(
                payload=payload
            ), tempfile.TemporaryDirectory() as temporary:
                bundle = make_bundle(
                    "verify-checksum-manifest-v1",
                    {"output/report.jsonl": self.ORACLE},
                )
                with materialize_fixture(
                    bundle.definition, Path(temporary) / "workspace"
                ) as handle:
                    write_outputs(
                        handle,
                        bundle,
                        payloads={"output/report.jsonl": payload},
                    )
                    evidence = verify_executable_fixture(bundle, handle)
                    self.assertEqual(
                        evidence.failure_code, "malformed-semantic-output"
                    )

    def test_checksum_jsonl_valid_record_difference_is_semantic_mismatch(self) -> None:
        actual = (
            b'{"path":"a","status":"checksum_mismatch"}\n'
            b'{"path":"b","status":"missing"}\n'
        )
        bundle = make_bundle(
            "verify-checksum-manifest-v1", {"output/report.jsonl": self.ORACLE}
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(
                bundle.definition, Path(temporary) / "workspace"
            ) as handle:
                write_outputs(
                    handle,
                    bundle,
                    payloads={"output/report.jsonl": actual},
                )
                evidence = verify_executable_fixture(bundle, handle)
                self.assertEqual(evidence.failure_code, "semantic-mismatch")

    def test_checksum_jsonl_rejects_an_unknown_status_in_the_trusted_oracle(self) -> None:
        path = "output/report.jsonl"
        bundle = make_bundle(
            "verify-checksum-manifest-v1",
            {path: b'{"path":"a","status":"invented"}\n'},
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(
                bundle.definition, Path(temporary) / "workspace"
            ) as handle:
                write_outputs(handle, bundle)
                evidence = verify_executable_fixture(bundle, handle)
                self.assertEqual(
                    evidence.failure_code, "trusted-oracle-invalid"
                )


class WorkspaceIntegrityTests(unittest.TestCase):
    def test_input_mutation_before_verification_is_a_distinct_failure(self) -> None:
        bundle = make_bundle(
            "verify-active-jsonl-labels-v1", {"output/labels.txt": b"ok\n"}
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(
                bundle.definition, Path(temporary) / "workspace"
            ) as handle:
                write_outputs(handle, bundle)
                source = handle.workspace / "input" / "source.txt"
                source.write_bytes(b"tampered-input\n")
                source.chmod(0o640)
                evidence = verify_executable_fixture(bundle, handle)
                self.assertEqual(evidence.failure_code, "input-baseline-mismatch")
                self.assertEqual(evidence.outputs, ())

    def test_input_mutation_during_output_read_is_caught_by_final_scan(self) -> None:
        bundle = make_bundle(
            "verify-active-jsonl-labels-v1", {"output/labels.txt": b"ok\n"}
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(
                bundle.definition, Path(temporary) / "workspace"
            ) as handle:
                write_outputs(handle, bundle)
                original = WorkspaceHandle.read_output_bytes
                changed = False

                def mutating_read(
                    selected: WorkspaceHandle, scan: object, path: str
                ) -> bytes:
                    nonlocal changed
                    payload = original(selected, scan, path)  # type: ignore[arg-type]
                    if not changed:
                        changed = True
                        source = selected.workspace / "input" / "source.txt"
                        source.write_bytes(b"changed-during-read\n")
                        source.chmod(0o640)
                    return payload

                with mock.patch.object(
                    WorkspaceHandle, "read_output_bytes", new=mutating_read
                ):
                    evidence = verify_executable_fixture(bundle, handle)
                self.assertTrue(changed)
                self.assertEqual(evidence.failure_code, "input-baseline-mismatch")

    def test_wrong_workspace_binding_fails_before_semantic_claim(self) -> None:
        bundle = make_bundle(
            "verify-active-jsonl-labels-v1", {"output/labels.txt": b"ok\n"}
        )
        other = make_bundle(
            "verify-active-jsonl-labels-v1",
            {"output/labels.txt": b"ok\n"},
            fixture_id="fixture.different-label",
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(
                other.definition, Path(temporary) / "workspace"
            ) as handle:
                write_outputs(handle, other)
                evidence = verify_executable_fixture(bundle, handle)
                self.assertEqual(evidence.failure_code, "workspace-binding-mismatch")

    def test_output_policy_and_read_infrastructure_failures_are_distinct(self) -> None:
        bundle = make_bundle(
            "verify-active-jsonl-labels-v1", {"output/labels.txt": b"ok\n"}
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(
                bundle.definition, Path(temporary) / "workspace"
            ) as handle:
                write_outputs(handle, bundle)
                (handle.workspace / "extra").write_bytes(b"extra")
                policy = verify_executable_fixture(bundle, handle)
                self.assertEqual(policy.failure_code, "output-policy-failure")

        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(
                bundle.definition, Path(temporary) / "workspace"
            ) as handle:
                write_outputs(handle, bundle)
                with mock.patch.object(
                    WorkspaceHandle,
                    "read_output_bytes",
                    side_effect=WorkspaceOutputReadError("injected"),
                ):
                    read = verify_executable_fixture(bundle, handle)
                self.assertEqual(read.failure_code, "output-read-failure")

    def test_oracle_mode_is_semantic_even_when_public_policy_mode_is_open(self) -> None:
        path = "output/labels.txt"
        bundle = make_bundle(
            "verify-active-jsonl-labels-v1",
            {path: b"ok\n"},
            expected_modes={path: None},
            oracle_modes={path: 0o640},
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(
                bundle.definition, Path(temporary) / "workspace"
            ) as handle:
                write_outputs(handle, bundle, modes={path: 0o600})
                evidence = verify_executable_fixture(bundle, handle)
                self.assertEqual(evidence.failure_code, "oracle-mode-mismatch")


class EvidenceContractTests(unittest.TestCase):
    def test_evidence_is_deterministic_self_addressed_and_non_authorizing(self) -> None:
        bundle = make_bundle(
            "verify-active-jsonl-labels-v1", {"output/labels.txt": b"ok\n"}
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(
                bundle.definition, Path(temporary) / "workspace"
            ) as handle:
                write_outputs(handle, bundle)
                with mock.patch.object(
                    subprocess, "run", side_effect=AssertionError("process executed")
                ), mock.patch.object(
                    subprocess, "Popen", side_effect=AssertionError("process executed")
                ), mock.patch.object(
                    os, "system", side_effect=AssertionError("shell executed")
                ):
                    first = verify_executable_fixture(bundle, handle)
                    second = verify_executable_fixture(bundle, handle)
                self.assertEqual(first, second)
                self.assertIsInstance(first, FixtureVerificationEvidence)
                self.assertTrue(
                    is_structurally_valid_fixture_verification_evidence(first)
                )
                validate_fixture_verification_evidence_structure(first)
                self.assertTrue(
                    is_fixture_verification_evidence_bound(first, bundle)
                )
                validate_fixture_verification_evidence_binding(first, bundle)
                json.dumps(first.to_record(), allow_nan=False)
                self.assertIs(first.candidate_execution_authorized, False)
                self.assertIs(first.model_selection_eligible, False)
                self.assertIs(first.claim_authorized, False)

                with self.assertRaisesRegex(
                    ExecutableFixtureVerificationError, "evidence_sha256"
                ):
                    replace(first, evidence_sha256="0" * 64)
                with self.assertRaisesRegex(
                    ExecutableFixtureVerificationError, "required output"
                ):
                    replace(first, outputs=())
                for mutation in (
                    {"candidate_execution_authorized": True},
                    {"model_selection_eligible": True},
                    {"claim_authorized": True},
                ):
                    with self.subTest(mutation=mutation), self.assertRaisesRegex(
                        ExecutableFixtureVerificationError, "cannot authorize"
                    ):
                        replace(first, **mutation)

                forged = replace(first)
                object.__setattr__(forged, "task_contract_sha256", "f" * 64)
                object.__setattr__(
                    forged,
                    "evidence_sha256",
                    domain_sha256(
                        "cbds.executable-fixture.verification-evidence.v1",
                        forged._core_record(),
                    ),
                )
                self.assertTrue(
                    is_structurally_valid_fixture_verification_evidence(forged)
                )
                self.assertFalse(
                    is_fixture_verification_evidence_bound(forged, bundle)
                )

    def test_bundle_is_revalidated_before_workspace_evidence(self) -> None:
        bundle = make_bundle(
            "verify-active-jsonl-labels-v1", {"output/labels.txt": b"ok\n"}
        )
        object.__setattr__(bundle.oracle, "oracle_sha256", "0" * 64)
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(
                bundle.definition, Path(temporary) / "workspace"
            ) as handle:
                write_outputs(handle, bundle)
                with self.assertRaisesRegex(
                    ExecutableFixtureVerificationError, "precondition revalidation"
                ):
                    verify_executable_fixture(bundle, handle)


if __name__ == "__main__":
    unittest.main()
