from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_fixture_bundle import (  # noqa: E402
    SEMANTIC_VERIFIER_IDENTITIES,
    ExecutableFixtureBundle,
    ExecutableFixtureBundleError,
    OracleOutputRecord,
    TrustedFixtureOracle,
    build_executable_fixture_bundle,
    build_trusted_fixture_oracle,
    compute_bound_fixture_sha256,
    compute_fixture_definition_semantic_sha256,
    compute_trusted_oracle_sha256,
    fixture_definition_semantic_record,
    validate_executable_fixture_bundle,
    validate_opaque_fixture_descriptor,
    verify_executable_fixture_bundle,
)
from cbds.executable_static_types import OpaqueFixtureDescriptor  # noqa: E402
from cbds.executable_workspace import (  # noqa: E402
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
)


TASK_SHA256 = "1" * 64
PROFILE_SHA256 = "2" * 64
VERIFIER = "verify-checksum-manifest-v1"


def sample_definition(
    fixture_id: str = "fixture.binding-alpha",
    *,
    input_content: bytes = b"input-payload\n",
    summary_maximum: int = 128,
    reverse_entries: bool = False,
) -> FixtureDefinition:
    inputs = (
        InputFile("input/data.txt", input_content, 0o640),
        InputSymlink("input/data-link", "data.txt"),
    )
    expected = (
        ExpectedFile("output/report.txt", maximum_bytes=64, mode=0o640),
        ExpectedFile("summary.json", maximum_bytes=summary_maximum),
    )
    if reverse_entries:
        inputs = tuple(reversed(inputs))
        expected = tuple(reversed(expected))
    return FixtureDefinition(
        fixture_id=fixture_id,
        inputs=inputs,
        expected_files=expected,
    )


def sample_oracle(
    *,
    report_content: bytes = b"report-body\n",
    report_mode: int = 0o640,
    summary_content: bytes = b'{"ok":true}\n',
    summary_mode: int = 0o644,
    verifier: str = VERIFIER,
) -> TrustedFixtureOracle:
    return build_trusted_fixture_oracle(
        (
            OracleOutputRecord("output/report.txt", report_content, report_mode),
            OracleOutputRecord("summary.json", summary_content, summary_mode),
        ),
        semantic_verifier_identity=verifier,  # type: ignore[arg-type]
    )


def sample_bundle(
    *,
    task_sha256: str = TASK_SHA256,
    profile_sha256: str = PROFILE_SHA256,
    definition: FixtureDefinition | None = None,
    oracle: TrustedFixtureOracle | None = None,
) -> ExecutableFixtureBundle:
    return build_executable_fixture_bundle(
        task_contract_sha256=task_sha256,
        profile_sha256=profile_sha256,
        definition=sample_definition() if definition is None else definition,
        oracle=sample_oracle() if oracle is None else oracle,
    )


class BindingIdentityTests(unittest.TestCase):
    def test_builds_one_self_recomputed_public_descriptor(self) -> None:
        bundle = sample_bundle()
        validate_executable_fixture_bundle(bundle)
        self.assertTrue(verify_executable_fixture_bundle(bundle))
        descriptor = bundle.to_opaque_descriptor()
        self.assertIs(type(descriptor), OpaqueFixtureDescriptor)
        self.assertEqual(descriptor.fixture_id, f"fx-{descriptor.fixture_sha256[:24]}")
        self.assertEqual(descriptor.task_contract_sha256, TASK_SHA256)
        self.assertEqual(
            bundle.fixture_definition_sha256,
            compute_fixture_definition_semantic_sha256(bundle.definition),
        )
        self.assertEqual(
            bundle.oracle.oracle_sha256,
            compute_trusted_oracle_sha256(
                bundle.oracle.outputs,
                bundle.oracle.semantic_verifier_identity,
            ),
        )
        self.assertEqual(
            descriptor.fixture_sha256,
            compute_bound_fixture_sha256(
                task_contract_sha256=TASK_SHA256,
                profile_sha256=PROFILE_SHA256,
                fixture_definition_sha256=bundle.fixture_definition_sha256,
                oracle_sha256=bundle.oracle.oracle_sha256,
            ),
        )
        validate_opaque_fixture_descriptor(bundle, descriptor)

    def test_private_commitment_exposes_hashes_not_oracle_bytes_or_label_salt(self) -> None:
        bundle = sample_bundle()
        encoded = json.dumps(bundle.commitment_record(), sort_keys=True)
        self.assertNotIn("report-body", encoded)
        self.assertNotIn('{"ok":true}', encoded)
        self.assertNotIn("fixture.binding-alpha", encoded)
        self.assertNotIn("report-body", repr(bundle.oracle.outputs[0]))
        semantic = fixture_definition_semantic_record(bundle.definition)
        self.assertNotIn("fixture_id", semantic)
        self.assertEqual(
            semantic["record_type"],
            "cbds.executable-fixture-definition-semantics",
        )

    def test_fixture_label_and_definition_tuple_order_cannot_salt_identity(self) -> None:
        first = sample_bundle(definition=sample_definition("fixture.binding-alpha"))
        relabeled = sample_bundle(
            definition=sample_definition(
                "fixture.binding-beta", reverse_entries=True
            )
        )
        self.assertNotEqual(first.definition.fixture_id, relabeled.definition.fixture_id)
        self.assertEqual(
            first.fixture_definition_sha256,
            relabeled.fixture_definition_sha256,
        )
        self.assertEqual(first.descriptor, relabeled.descriptor)

    def test_every_semantic_commitment_changes_the_public_identity(self) -> None:
        baseline = sample_bundle()
        variants = (
            sample_bundle(task_sha256="3" * 64),
            sample_bundle(profile_sha256="4" * 64),
            sample_bundle(
                definition=sample_definition(input_content=b"different-input\n")
            ),
            sample_bundle(
                definition=sample_definition(summary_maximum=129)
            ),
            sample_bundle(oracle=sample_oracle(report_content=b"different\n")),
            sample_bundle(oracle=sample_oracle(summary_mode=0o600)),
            sample_bundle(
                oracle=sample_oracle(verifier="verify-active-jsonl-labels-v1")
            ),
        )
        for variant in variants:
            with self.subTest(variant=variant.descriptor.fixture_id):
                self.assertNotEqual(
                    baseline.descriptor.fixture_sha256,
                    variant.descriptor.fixture_sha256,
                )

    def test_all_authorization_and_claim_flags_are_hard_false(self) -> None:
        bundle = sample_bundle()
        self.assertIs(bundle.candidate_execution_authorized, False)
        self.assertIs(bundle.model_selection_eligible, False)
        self.assertIs(bundle.claim_authorized, False)
        for mutation in (
            {"candidate_execution_authorized": True},
            {"model_selection_eligible": True},
            {"claim_authorized": True},
        ):
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                ExecutableFixtureBundleError, "cannot authorize"
            ):
                replace(bundle, **mutation)


class OraclePolicyTests(unittest.TestCase):
    def test_oracle_paths_must_exactly_match_expected_file_policy(self) -> None:
        definition = sample_definition()
        missing = build_trusted_fixture_oracle(
            (OracleOutputRecord("output/report.txt", b"ok", 0o640),),
            semantic_verifier_identity=VERIFIER,
        )
        extra = build_trusted_fixture_oracle(
            (
                OracleOutputRecord("output/report.txt", b"ok", 0o640),
                OracleOutputRecord("summary.json", b"{}\n", 0o644),
                OracleOutputRecord("zz-extra", b"extra", 0o644),
            ),
            semantic_verifier_identity=VERIFIER,
        )
        for oracle in (missing, extra):
            with self.subTest(paths=[item.path for item in oracle.outputs]):
                with self.assertRaisesRegex(
                    ExecutableFixtureBundleError, "exactly match"
                ):
                    sample_bundle(definition=definition, oracle=oracle)

    def test_oracle_enforces_per_path_size_and_mode_policy(self) -> None:
        oversized = sample_oracle(report_content=b"x" * 65)
        wrong_mode = sample_oracle(report_mode=0o644)
        with self.assertRaisesRegex(
            ExecutableFixtureBundleError, "maximum_bytes"
        ):
            sample_bundle(oracle=oversized)
        with self.assertRaisesRegex(ExecutableFixtureBundleError, "mode differs"):
            sample_bundle(oracle=wrong_mode)

    def test_oracle_output_paths_are_unique_and_canonically_sorted(self) -> None:
        duplicate = (
            OracleOutputRecord("same", b"a"),
            OracleOutputRecord("same", b"b"),
        )
        unsorted = tuple(reversed(sample_oracle().outputs))
        with self.assertRaisesRegex(ExecutableFixtureBundleError, "not unique"):
            build_trusted_fixture_oracle(
                duplicate,
                semantic_verifier_identity=VERIFIER,
            )
        with self.assertRaisesRegex(ExecutableFixtureBundleError, "canonically sorted"):
            build_trusted_fixture_oracle(
                unsorted,
                semantic_verifier_identity=VERIFIER,
            )

    def test_verifier_identity_is_a_closed_implementation_choice(self) -> None:
        self.assertEqual(len(SEMANTIC_VERIFIER_IDENTITIES), 10)
        self.assertIn(
            "verify-line-transform-mirror-v1",
            SEMANTIC_VERIFIER_IDENTITIES,
        )
        with self.assertRaisesRegex(ExecutableFixtureBundleError, "closed verifier"):
            build_trusted_fixture_oracle(
                (OracleOutputRecord("answer", b"ok"),),
                semantic_verifier_identity="custom-verifier",  # type: ignore[arg-type]
            )


class ExactTypeAndTamperTests(unittest.TestCase):
    def test_mutable_or_subclassed_oracle_values_are_rejected(self) -> None:
        output = OracleOutputRecord("answer", b"ok")
        with self.assertRaisesRegex(ExecutableFixtureBundleError, "immutable bytes"):
            OracleOutputRecord("answer", bytearray(b"ok"))  # type: ignore[arg-type]
        with self.assertRaisesRegex(ExecutableFixtureBundleError, "exact tuple"):
            build_trusted_fixture_oracle(
                [output],  # type: ignore[arg-type]
                semantic_verifier_identity=VERIFIER,
            )

        class OutputSubclass(OracleOutputRecord):
            pass

        subclassed = OutputSubclass("answer", b"ok")
        with self.assertRaisesRegex(ExecutableFixtureBundleError, "exact tuple"):
            build_trusted_fixture_oracle(
                (subclassed,),
                semantic_verifier_identity=VERIFIER,
            )

    def test_definition_and_oracle_must_be_exact_closed_types(self) -> None:
        class DefinitionSubclass(FixtureDefinition):
            pass

        original = sample_definition()
        subclassed_definition = DefinitionSubclass(
            fixture_id=original.fixture_id,
            inputs=original.inputs,
            expected_files=original.expected_files,
        )
        with self.assertRaisesRegex(ExecutableFixtureBundleError, "exact FixtureDefinition"):
            sample_bundle(definition=subclassed_definition)

        class OracleSubclass(TrustedFixtureOracle):
            pass

        original_oracle = sample_oracle()
        subclassed_oracle = OracleSubclass(
            outputs=original_oracle.outputs,
            semantic_verifier_identity=original_oracle.semantic_verifier_identity,
            oracle_sha256=original_oracle.oracle_sha256,
        )
        with self.assertRaisesRegex(ExecutableFixtureBundleError, "exact Trusted"):
            sample_bundle(oracle=subclassed_oracle)

    def test_stored_hashes_and_descriptor_are_recomputed(self) -> None:
        oracle = sample_oracle()
        with self.assertRaisesRegex(ExecutableFixtureBundleError, "oracle_sha256"):
            TrustedFixtureOracle(
                outputs=oracle.outputs,
                semantic_verifier_identity=oracle.semantic_verifier_identity,
                oracle_sha256="0" * 64,
            )

        bundle = sample_bundle()
        with self.assertRaisesRegex(
            ExecutableFixtureBundleError, "fixture_definition_sha256"
        ):
            replace(bundle, fixture_definition_sha256="0" * 64)

        other = sample_bundle(profile_sha256="9" * 64)
        with self.assertRaisesRegex(ExecutableFixtureBundleError, "descriptor does not match"):
            replace(bundle, descriptor=other.descriptor)
        with self.assertRaisesRegex(ExecutableFixtureBundleError, "descriptor differs"):
            validate_opaque_fixture_descriptor(bundle, other.descriptor)

    def test_revalidation_detects_frozen_object_bypass_tampering(self) -> None:
        oracle_tampered = sample_bundle()
        object.__setattr__(oracle_tampered.oracle, "oracle_sha256", "0" * 64)
        self.assertFalse(verify_executable_fixture_bundle(oracle_tampered))

        descriptor_tampered = sample_bundle()
        object.__setattr__(
            descriptor_tampered.descriptor,
            "schema_version",
            "tampered",
        )
        self.assertFalse(verify_executable_fixture_bundle(descriptor_tampered))

        output_tampered = sample_bundle()
        object.__setattr__(
            output_tampered.oracle.outputs[0],
            "content",
            bytearray(b"mutable"),
        )
        self.assertFalse(verify_executable_fixture_bundle(output_tampered))

        definition_tampered = sample_bundle()
        object.__setattr__(
            definition_tampered.definition.inputs[0],
            "content",
            bytearray(b"mutable"),
        )
        self.assertFalse(verify_executable_fixture_bundle(definition_tampered))

    def test_external_descriptor_subclasses_are_rejected(self) -> None:
        class DescriptorSubclass(OpaqueFixtureDescriptor):
            pass

        bundle = sample_bundle()
        descriptor = bundle.descriptor
        subclassed = DescriptorSubclass(
            fixture_id=descriptor.fixture_id,
            fixture_sha256=descriptor.fixture_sha256,
            task_contract_sha256=descriptor.task_contract_sha256,
        )
        with self.assertRaisesRegex(ExecutableFixtureBundleError, "exact Opaque"):
            validate_opaque_fixture_descriptor(bundle, subclassed)


if __name__ == "__main__":
    unittest.main()
