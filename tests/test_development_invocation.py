from __future__ import annotations

import base64
import copy
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.development_invocation import (  # noqa: E402
    BLOCKED_RESULT_FRAME_MAGIC,
    FRAME_HEADER_BYTES,
    INVOCATION_FRAME_MAGIC,
    MAXIMUM_FRAME_PAYLOAD_BYTES,
    MAXIMUM_JSON_NODES,
    DevelopmentInvocationBlocked,
    DevelopmentInvocationError,
    admit_development_catalog,
    build_blocked_development_result,
    build_development_invocation,
    decode_blocked_development_result_frame,
    decode_development_invocation_frame,
    encode_blocked_development_result_frame,
    encode_development_invocation_frame,
    refuse_development_invocation,
    validate_development_invocation_record_against_catalog,
    verify_development_invocation,
)
import cbds.development_invocation as invocation_module  # noqa: E402
from cbds.executable_fixture_catalog import (  # noqa: E402
    build_first_tranche_fixture_catalog,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_static_registry import (  # noqa: E402
    build_public_method_development_registry,
)
from cbds.executable_static_types import domain_sha256  # noqa: E402
from cbds.executable_workspace import InputFile, InputHardlink  # noqa: E402


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def invocation_rehash(record: dict[str, object]) -> None:
    unsigned = copy.deepcopy(record)
    unsigned.pop("invocation_sha256", None)
    record["invocation_sha256"] = domain_sha256(
        "cbds.development-invocation.request.v1", unsigned
    )


def frame_record(record: dict[str, object], magic: bytes = INVOCATION_FRAME_MAGIC) -> bytes:
    payload = canonical(record)
    return magic + struct.pack(">Q", len(payload)) + payload


def record_from_frame(frame: bytes) -> dict[str, object]:
    return json.loads(frame[FRAME_HEADER_BYTES:].decode("utf-8"))


class DevelopmentInvocationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = build_first_tranche_fixture_catalog(
            build_public_method_development_registry()
        )
        cls.admission = admit_development_catalog(cls.catalog)
        cls.bundle = cls.catalog.bundles[0]
        cls.marker = "PRIVATE_PROGRAM_MARKER_4471"
        cls.invocation = build_development_invocation(
            cls.admission,
            fixture_id=cls.bundle.descriptor.fixture_id,
            response_text=f"```bash\nprintf '%s\\n' {cls.marker}\n```",
        )
        cls.frame = encode_development_invocation_frame(cls.invocation)
        cls.record = record_from_frame(cls.frame)

    def test_exact_catalog_fixture_and_frozen_parser_are_bound(self) -> None:
        invocation = self.invocation
        self.assertTrue(verify_development_invocation(invocation))
        self.assertEqual(
            invocation.bundle.descriptor.fixture_id,
            self.bundle.descriptor.fixture_id,
        )
        self.assertEqual(
            invocation.task.task_contract_sha256,
            self.bundle.task_contract_sha256,
        )
        self.assertEqual(invocation.profile.profile_sha256, self.bundle.profile_sha256)
        self.assertEqual(invocation.program.decode(), f"printf '%s\\n' {self.marker}")
        self.assertTrue(invocation.fenced)
        for name in (
            "candidate_execution_authorized",
            "candidate_executed",
            "scored_evaluation_eligible",
            "model_selection_eligible",
            "claim_pipeline_eligible",
        ):
            self.assertIs(getattr(invocation, name), False)

    def test_all_five_current_families_and_path_fixture_are_catalog_bound(self) -> None:
        family_ids = {
            "active-jsonl-labels",
            "manifest-copy",
            "csv-group-totals",
            "checksum-manifest",
            "path-suffix-inventory",
        }
        self.assertEqual(
            {task.family_id for task in self.catalog.source_registry.tasks}, family_ids
        )
        path_task = next(
            task
            for task in self.catalog.source_registry.tasks
            if task.family_id == "path-suffix-inventory"
        )
        bundle = next(
            bundle
            for bundle in self.catalog.bundles
            if bundle.task_contract_sha256 == path_task.task_contract_sha256
        )
        invocation = build_development_invocation(
            self.admission,
            fixture_id=bundle.descriptor.fixture_id,
            response_text="mkdir -p output\n",
        )
        self.assertEqual(invocation.task.family_id, "path-suffix-inventory")

    def test_audit_record_retains_no_program_fixture_or_oracle_bytes(self) -> None:
        audit = self.invocation.to_audit_record()
        serialized = canonical(audit)
        self.assertNotIn(self.marker.encode(), serialized)
        self.assertNotIn(b"content_base64", serialized)
        self.assertNotIn(b"oracle_sha256", serialized)
        self.assertNotIn(b"outputs", serialized)
        self.assertEqual(audit["program_sha256"], self.invocation.program_sha256)
        self.assertEqual(audit["fixture_sha256"], self.bundle.descriptor.fixture_sha256)

        private_record = self.invocation.to_protocol_record()
        private_serialized = canonical(private_record)
        self.assertIn(self.marker.encode(), base64.b64decode(private_record["program"]["content_base64"]))  # type: ignore[index]
        self.assertNotIn(b"oracle_sha256", private_serialized)
        for output in self.bundle.oracle.outputs:
            if output.content:
                self.assertNotIn(base64.b64encode(output.content), private_serialized)

    def test_request_frame_round_trip_is_canonical_and_catalog_bound(self) -> None:
        self.assertEqual(self.frame[:8], INVOCATION_FRAME_MAGIC)
        declared = struct.unpack(">Q", self.frame[8:16])[0]
        self.assertEqual(declared, len(self.frame) - FRAME_HEADER_BYTES)
        decoded = decode_development_invocation_frame(
            self.frame, catalog=self.admission
        )
        self.assertEqual(decoded, self.record)
        self.assertEqual(canonical(decoded), self.frame[FRAME_HEADER_BYTES:])
        validate_development_invocation_record_against_catalog(
            decoded, self.admission
        )

    def test_v1_protocol_fails_closed_on_unrepresentable_input_extensions(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            DevelopmentInvocationError,
            "does not carry committed input mtimes",
        ):
            invocation_module._input_protocol_record(
                InputFile(
                    "input/file",
                    b"content",
                    mtime_seconds=123,
                )
            )
        with self.assertRaisesRegex(
            DevelopmentInvocationError,
            "input type",
        ):
            invocation_module._input_protocol_record(  # type: ignore[arg-type]
                InputHardlink("input/alias", "input/0-source")
            )

    def test_parser_floor_and_frozen_response_ceiling_fail_closed(self) -> None:
        cases = (
            {"response_text": ""},
            {"response_text": "```python\nprint('no')\n```"},
            {"response_text": "```bash\necho partial", "was_truncated": True},
            {"response_text": "echo ok", "maximum_response_bytes": 65_537},
            {"response_text": "echo ok\x00echo no"},
        )
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(DevelopmentInvocationError):
                    build_development_invocation(
                        self.admission,
                        fixture_id=self.bundle.descriptor.fixture_id,
                        **kwargs,
                    )

    def test_unknown_and_legacy_shaped_fixture_ids_are_rejected(self) -> None:
        for fixture_id in (
            "fx-000000000000000000000000",
            "fixture-old-family",
            self.bundle.descriptor.fixture_id[:-1],
        ):
            with self.subTest(fixture_id=fixture_id):
                with self.assertRaises(DevelopmentInvocationError):
                    build_development_invocation(
                        self.admission,
                        fixture_id=fixture_id,
                        response_text="echo ok",
                    )

    def test_rehashed_cross_task_profile_and_legacy_family_substitution_fail(self) -> None:
        second = self.catalog.bundles[5]
        other_task = next(
            task
            for task in self.catalog.source_registry.tasks
            if task.task_contract_sha256 == second.task_contract_sha256
        )
        mutations: list[dict[str, object]] = []

        cross_task = copy.deepcopy(self.record)
        cross_task["task"] = {
            "task_id": other_task.task_id,
            "family_id": other_task.family_id,
            "task_contract_sha256": other_task.task_contract_sha256,
            "graph_sha256": other_task.graph_sha256,
        }
        mutations.append(cross_task)

        cross_profile = copy.deepcopy(self.record)
        other_profile = self.catalog.bundles[1]
        profile = next(
            profile
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
            if profile.profile_sha256 == other_profile.profile_sha256
        )
        cross_profile["profile"] = {
            "profile_id": profile.profile_id,
            "profile_sha256": profile.profile_sha256,
        }
        mutations.append(cross_profile)

        legacy = copy.deepcopy(self.record)
        legacy["task"]["family_id"] = "copy-map"  # type: ignore[index]
        mutations.append(legacy)

        for mutation in mutations:
            invocation_rehash(mutation)
            with self.subTest(task=mutation["task"], profile=mutation["profile"]):
                with self.assertRaises(DevelopmentInvocationError):
                    decode_development_invocation_frame(
                        frame_record(mutation), catalog=self.admission
                    )

    def test_rehashed_workspace_tool_policy_and_authority_mutations_fail(self) -> None:
        mutations: list[dict[str, object]] = []

        tool = copy.deepcopy(self.record)
        tool["tool_policy"]["allowed_tools"] = ["curl"]  # type: ignore[index]
        tool["tool_policy"]["allowed_tools_sha256"] = domain_sha256(  # type: ignore[index]
            "cbds.development-invocation.allowed-tools.v1",
            {"allowed_tools": ["curl"]},
        )
        mutations.append(tool)

        authority = copy.deepcopy(self.record)
        authority["candidate_execution_authorized"] = True
        mutations.append(authority)

        workspace = copy.deepcopy(self.record)
        file_entry = next(
            entry
            for entry in workspace["workspace"]["inputs"]  # type: ignore[index]
            if entry["kind"] == "file"
        )
        file_entry["content_base64"] = base64.b64encode(b"changed").decode()
        file_entry["size"] = 7
        file_entry["sha256"] = sha256(b"changed").hexdigest()
        mutations.append(workspace)

        for mutation in mutations:
            invocation_rehash(mutation)
            with self.assertRaises(DevelopmentInvocationError):
                decode_development_invocation_frame(
                    frame_record(mutation), catalog=self.admission
                )

    def test_rehashed_program_must_remain_a_frozen_parser_fixed_point(self) -> None:
        for payload in (
            b"   ",
            b"```bash\necho hidden\n```",
            b"echo normalized\r\n",
        ):
            with self.subTest(payload=payload):
                mutation = copy.deepcopy(self.record)
                mutation["program"].update(  # type: ignore[union-attr]
                    {
                        "content_base64": base64.b64encode(payload).decode(),
                        "bytes": len(payload),
                        "sha256": sha256(payload).hexdigest(),
                        "response_bytes": len(payload),
                        "fenced": False,
                    }
                )
                invocation_rehash(mutation)
                with self.assertRaises(DevelopmentInvocationError):
                    decode_development_invocation_frame(
                        frame_record(mutation), catalog=self.admission
                    )

        for field, value in (
            ("fenced", False),
            ("response_bytes", self.record["program"]["response_bytes"] + 1),  # type: ignore[index]
        ):
            with self.subTest(field=field):
                mutation = copy.deepcopy(self.record)
                mutation["program"][field] = value  # type: ignore[index]
                invocation_rehash(mutation)
                with self.assertRaises(DevelopmentInvocationError):
                    decode_development_invocation_frame(
                        frame_record(mutation), catalog=self.admission
                    )

    def test_frame_fails_on_every_truncation_and_on_length_or_magic_errors(self) -> None:
        for length in range(len(self.frame)):
            with self.assertRaises(DevelopmentInvocationError):
                decode_development_invocation_frame(
                    self.frame[:length], catalog=self.admission
                )

        malformed = (
            b"BADMAGIC" + self.frame[8:],
            self.frame[:8] + struct.pack(">Q", 0) + self.frame[16:],
            self.frame[:8] + struct.pack(">Q", MAXIMUM_FRAME_PAYLOAD_BYTES + 1),
            self.frame + b"trailing",
        )
        for frame in malformed:
            with self.subTest(size=len(frame)):
                with self.assertRaises(DevelopmentInvocationError):
                    decode_development_invocation_frame(frame, catalog=self.admission)

    def test_duplicate_json_keys_noncanonical_json_and_bad_base64_fail(self) -> None:
        duplicate_payload = b'{"kind":"a","kind":"b"}'
        duplicate = (
            INVOCATION_FRAME_MAGIC
            + struct.pack(">Q", len(duplicate_payload))
            + duplicate_payload
        )
        with self.assertRaises(DevelopmentInvocationError):
            decode_development_invocation_frame(duplicate, catalog=self.admission)

        pretty_payload = json.dumps(self.record, indent=2).encode()
        pretty = INVOCATION_FRAME_MAGIC + struct.pack(">Q", len(pretty_payload)) + pretty_payload
        with self.assertRaises(DevelopmentInvocationError):
            decode_development_invocation_frame(pretty, catalog=self.admission)

        nested: object = "leaf"
        for _ in range(40):
            nested = [nested]
        nested_payload = canonical({"nested": nested})
        nested_frame = (
            INVOCATION_FRAME_MAGIC
            + struct.pack(">Q", len(nested_payload))
            + nested_payload
        )
        with mock.patch("cbds.development_invocation.json.loads") as loads:
            with self.assertRaises(DevelopmentInvocationError):
                decode_development_invocation_frame(
                    nested_frame, catalog=self.admission
                )
            loads.assert_not_called()

        wide_payload = b"[" + b"0," * (2 * MAXIMUM_JSON_NODES + 1) + b"0]"
        wide_frame = (
            INVOCATION_FRAME_MAGIC
            + struct.pack(">Q", len(wide_payload))
            + wide_payload
        )
        with mock.patch("cbds.development_invocation.json.loads") as loads:
            with self.assertRaises(DevelopmentInvocationError):
                decode_development_invocation_frame(
                    wide_frame, catalog=self.admission
                )
            loads.assert_not_called()

        invalid = copy.deepcopy(self.record)
        invalid["program"]["content_base64"] = "!!!!"  # type: ignore[index]
        invocation_rehash(invalid)
        with self.assertRaises(DevelopmentInvocationError):
            decode_development_invocation_frame(
                frame_record(invalid), catalog=self.admission
            )

    def test_low_level_frozen_object_bypass_is_revalidated(self) -> None:
        original = self.invocation.response_bytes
        try:
            object.__setattr__(self.invocation, "response_bytes", 0)
            self.assertFalse(verify_development_invocation(self.invocation))
            with self.assertRaises(DevelopmentInvocationError):
                encode_development_invocation_frame(self.invocation)
        finally:
            object.__setattr__(self.invocation, "response_bytes", original)
        self.assertTrue(verify_development_invocation(self.invocation))

    def test_rehashed_invocation_cannot_hide_a_mutated_catalog(self) -> None:
        original_catalog = self.catalog.catalog_sha256
        original_invocation = self.invocation.invocation_sha256
        try:
            object.__setattr__(self.catalog, "catalog_sha256", "0" * 64)
            forged_record = copy.deepcopy(self.record)
            forged_record["catalog_sha256"] = "0" * 64
            invocation_rehash(forged_record)
            object.__setattr__(
                self.invocation,
                "invocation_sha256",
                forged_record["invocation_sha256"],
            )
            self.assertFalse(verify_development_invocation(self.invocation))
            with self.assertRaises(DevelopmentInvocationError):
                encode_development_invocation_frame(self.invocation)
        finally:
            object.__setattr__(self.catalog, "catalog_sha256", original_catalog)
            object.__setattr__(
                self.invocation, "invocation_sha256", original_invocation
            )
        self.assertTrue(verify_development_invocation(self.invocation))

    def test_low_level_catalog_admission_binding_mutation_is_rejected(self) -> None:
        original = self.admission.member_bindings
        fixture_id, _binding_sha256 = original[0]
        forged = ((fixture_id, "0" * 64),) + original[1:]
        try:
            object.__setattr__(self.admission, "member_bindings", forged)
            self.assertFalse(verify_development_invocation(self.invocation))
            with self.assertRaises(DevelopmentInvocationError):
                decode_development_invocation_frame(
                    self.frame,
                    catalog=self.admission,
                )
        finally:
            object.__setattr__(self.admission, "member_bindings", original)
        self.assertTrue(verify_development_invocation(self.invocation))

    def test_blocked_result_is_the_only_result_and_never_claims_execution(self) -> None:
        blockers = (
            "blocked_trusted_pid1_supervisor_missing",
            "blocked_child_seccomp_filter_missing",
        )
        result = build_blocked_development_result(self.invocation, blockers)
        frame = encode_blocked_development_result_frame(result)
        self.assertEqual(frame[:8], BLOCKED_RESULT_FRAME_MAGIC)
        self.assertEqual(
            decode_blocked_development_result_frame(
                frame,
                expected_invocation_sha256=self.invocation.invocation_sha256,
            ),
            result,
        )
        self.assertFalse(result["candidate_executed"])
        self.assertFalse(result["functional_verification_performed"])
        self.assertFalse(result["claim_pipeline_eligible"])

        mutated = copy.deepcopy(result)
        mutated["candidate_executed"] = True
        with self.assertRaises(DevelopmentInvocationError):
            encode_blocked_development_result_frame(mutated)
        with self.assertRaises(DevelopmentInvocationError):
            decode_blocked_development_result_frame(
                frame,
                expected_invocation_sha256="0" * 64,
            )
        with self.assertRaises(DevelopmentInvocationBlocked) as captured:
            refuse_development_invocation(self.invocation, blockers)
        self.assertEqual(captured.exception.blockers, blockers)


if __name__ == "__main__":
    unittest.main()
