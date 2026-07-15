from __future__ import annotations

from dataclasses import dataclass, fields
from hashlib import sha256
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_fixture_bundle import (  # noqa: E402
    ExecutableFixtureBundleError,
    validate_executable_fixture_bundle,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
    ExecutableFixtureProfile,
)
from cbds.executable_fixture_ustar import (  # noqa: E402
    ExecutableFixtureUstarError,
    build_ustar_safe_extract_fixture_bundle,
)
from cbds.executable_static_second_registry import (  # noqa: E402
    build_ustar_safe_extract_tasks,
)
from cbds.executable_static_types import (  # noqa: E402
    ExecutableStaticTask,
    UstarSafeExtractParameters,
)
from cbds.executable_workspace import InputFile, InputSymlink  # noqa: E402


SELECTORS = (
    "all-regular",
    "txt-suffix",
    "jsonl-suffix",
    "nonempty-regular",
)
CONFLICT_POLICIES = (
    "reject-duplicates",
    "first-entry",
    "last-entry",
    "identical-only",
    "smallest-sha256",
)
BLOCK_SIZE = 512


@dataclass(frozen=True)
class IndependentMember:
    ordinal: int
    name: str
    content: bytes
    typeflag: bytes


@dataclass(frozen=True)
class IndependentScan:
    regulars: tuple[IndependentMember, ...]
    stop_reason: str
    seen_typeflags: tuple[bytes, ...]
    unsafe_regular_names: tuple[str, ...]
    invalid_text_regular_name_count: int


def profile_by_id(profile_id: str) -> ExecutableFixtureProfile:
    matches = tuple(
        profile
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        if profile.profile_id == profile_id
    )
    if len(matches) != 1:
        raise AssertionError(f"expected one profile for {profile_id!r}")
    return matches[0]


def task_by_parameters(
    tasks: tuple[ExecutableStaticTask, ...],
    *,
    selector: str,
    conflict_policy: str,
) -> ExecutableStaticTask:
    matches = tuple(
        task
        for task in tasks
        if task.parameters.selector == selector
        and task.parameters.conflict_policy == conflict_policy
    )
    if len(matches) != 1:
        raise AssertionError(
            f"expected one ustar task for {selector=!r}, {conflict_policy=!r}"
        )
    return matches[0]


def archive_input(bundle: object) -> InputFile:
    matches = tuple(
        item
        for item in bundle.definition.inputs
        if type(item) is InputFile and item.path == "input/archive.tar"
    )
    if len(matches) != 1:
        raise AssertionError("fixture does not contain exactly one archive input")
    return matches[0]


def independent_octal(field: bytes) -> int | None:
    value = field.strip(b"\0 ")
    if not value or any(byte not in b"01234567" for byte in value):
        return None
    return int(value, 8)


def independent_text(field: bytes) -> str | None:
    raw, separator, tail = field.partition(b"\0")
    if separator and tail.strip(b"\0"):
        return None
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def independent_name(header: bytes) -> str | None:
    leaf = independent_text(header[:100])
    prefix = independent_text(header[345:500])
    if leaf is None or prefix is None or leaf == "":
        return None
    return prefix + "/" + leaf if prefix else leaf


def independently_safe(name: str | None) -> bool:
    if name is None or name.startswith("/") or name.endswith("/"):
        return False
    pieces = name.split("/")
    if any(piece in {"", ".", ".."} for piece in pieces):
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        return False
    try:
        return PurePosixPath(name).as_posix() == name and bool(
            name.encode("utf-8", errors="strict")
        )
    except UnicodeEncodeError:
        return False


def independently_scan_archive(archive: bytes) -> IndependentScan:
    regulars: list[IndependentMember] = []
    typeflags: list[bytes] = []
    unsafe: list[str] = []
    invalid_text_names = 0
    offset = 0
    ordinal = 0
    while True:
        remaining = len(archive) - offset
        if remaining == 0:
            return IndependentScan(
                tuple(regulars), "missing-end-marker", tuple(typeflags), tuple(unsafe), invalid_text_names
            )
        if remaining < BLOCK_SIZE:
            return IndependentScan(
                tuple(regulars), "truncated-header", tuple(typeflags), tuple(unsafe), invalid_text_names
            )
        header = archive[offset : offset + BLOCK_SIZE]
        if not any(header):
            return IndependentScan(
                tuple(regulars), "end-of-archive", tuple(typeflags), tuple(unsafe), invalid_text_names
            )
        expected_checksum = independent_octal(header[148:156])
        checksum_copy = bytearray(header)
        checksum_copy[148:156] = b" " * 8
        if expected_checksum is None or expected_checksum != sum(checksum_copy):
            return IndependentScan(
                tuple(regulars), "invalid-checksum", tuple(typeflags), tuple(unsafe), invalid_text_names
            )
        if header[257:263] != b"ustar\0" or header[263:265] != b"00":
            return IndependentScan(
                tuple(regulars), "invalid-header", tuple(typeflags), tuple(unsafe), invalid_text_names
            )
        size = independent_octal(header[124:136])
        if size is None:
            return IndependentScan(
                tuple(regulars), "invalid-header", tuple(typeflags), tuple(unsafe), invalid_text_names
            )
        padded = ((size + BLOCK_SIZE - 1) // BLOCK_SIZE) * BLOCK_SIZE
        content_start = offset + BLOCK_SIZE
        content_end = content_start + size
        next_offset = content_start + padded
        if content_end > len(archive) or next_offset > len(archive):
            return IndependentScan(
                tuple(regulars), "truncated-member", tuple(typeflags), tuple(unsafe), invalid_text_names
            )
        typeflag = header[156:157]
        typeflags.append(typeflag)
        name = independent_name(header)
        if typeflag in {b"0", b"\0"}:
            if independently_safe(name):
                if name is None:  # pragma: no cover - implied by the predicate
                    raise AssertionError("safe name unexpectedly absent")
                regulars.append(
                    IndependentMember(
                        ordinal,
                        name,
                        archive[content_start:content_end],
                        typeflag,
                    )
                )
            elif name is not None:
                unsafe.append(name)
            else:
                invalid_text_names += 1
        ordinal += 1
        offset = next_offset


def independent_selector(member: IndependentMember, selector: str) -> bool:
    basename = member.name.split("/")[-1]
    if selector == "all-regular":
        return True
    if selector == "txt-suffix":
        return basename.endswith(".txt")
    if selector == "jsonl-suffix":
        return basename.endswith(".jsonl")
    if selector == "nonempty-regular":
        return bool(member.content)
    raise AssertionError(f"unknown selector in test oracle: {selector!r}")


def independently_derive_outputs(
    task: ExecutableStaticTask,
    bundle: object,
) -> tuple[tuple[str, bytes, int], ...]:
    scan = independently_scan_archive(archive_input(bundle).content)
    grouped: dict[str, list[IndependentMember]] = {}
    for member in scan.regulars:
        if independent_selector(member, task.parameters.selector):
            grouped.setdefault(member.name, []).append(member)

    selected: list[tuple[str, bytes, int]] = []
    for name, members in grouped.items():
        chosen: IndependentMember | None
        if len(members) == 1:
            chosen = members[0]
        elif task.parameters.conflict_policy == "reject-duplicates":
            chosen = None
        elif task.parameters.conflict_policy == "first-entry":
            chosen = min(members, key=lambda member: member.ordinal)
        elif task.parameters.conflict_policy == "last-entry":
            chosen = max(members, key=lambda member: member.ordinal)
        elif task.parameters.conflict_policy == "identical-only":
            values = {member.content for member in members}
            chosen = min(members, key=lambda member: member.ordinal) if len(values) == 1 else None
        elif task.parameters.conflict_policy == "smallest-sha256":
            chosen = min(
                members,
                key=lambda member: (
                    sha256(member.content).hexdigest(),
                    member.ordinal,
                ),
            )
        else:
            raise AssertionError("unknown conflict policy in test oracle")
        if chosen is not None:
            selected.append(
                (f"output/extracted/{name}", chosen.content, 0o644)
            )
    return tuple(sorted(selected, key=lambda record: record[0].encode("utf-8")))


def exact_clone(instance: object):
    clone = object.__new__(type(instance))
    for field in fields(instance):
        object.__setattr__(clone, field.name, getattr(instance, field.name))
    return clone


class UstarSafeExtractFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = build_ustar_safe_extract_tasks()

    def test_all_20_by_5_bundles_are_exact_deterministic_and_nonexecuting(
        self,
    ) -> None:
        self.assertEqual(len(self.tasks), 20)
        self.assertEqual(
            {
                (task.parameters.selector, task.parameters.conflict_policy)
                for task in self.tasks
            },
            {
                (selector, conflict_policy)
                for selector in SELECTORS
                for conflict_policy in CONFLICT_POLICIES
            },
        )
        descriptors = []
        with mock.patch.object(
            subprocess,
            "run",
            side_effect=AssertionError("subprocess.run executed"),
        ), mock.patch.object(
            subprocess,
            "Popen",
            side_effect=AssertionError("subprocess.Popen executed"),
        ), mock.patch.object(
            os,
            "system",
            side_effect=AssertionError("os.system executed"),
        ), mock.patch.object(
            os,
            "popen",
            side_effect=AssertionError("os.popen executed"),
        ):
            tasks = build_ustar_safe_extract_tasks()
            for task in tasks:
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                    with self.subTest(
                        selector=task.parameters.selector,
                        conflict_policy=task.parameters.conflict_policy,
                        profile=profile.profile_id,
                    ):
                        first = build_ustar_safe_extract_fixture_bundle(task, profile)
                        second = build_ustar_safe_extract_fixture_bundle(task, profile)
                        self.assertEqual(first, second)
                        validate_executable_fixture_bundle(first)
                        self.assertEqual(
                            first.task_contract_sha256, task.task_contract_sha256
                        )
                        self.assertEqual(first.profile_sha256, profile.profile_sha256)
                        self.assertEqual(
                            first.oracle.semantic_verifier_identity,
                            "verify-ustar-safe-extract-v1",
                        )
                        expected = independently_derive_outputs(task, first)
                        observed = tuple(
                            (output.path, output.content, output.mode)
                            for output in first.oracle.outputs
                        )
                        self.assertEqual(observed, expected)
                        self.assertGreater(len(observed), 0)
                        self.assertEqual(
                            tuple(policy.path for policy in first.definition.expected_files),
                            tuple(path for path, _content, _mode in expected),
                        )
                        self.assertTrue(
                            all(
                                policy.mode == 0o644
                                and policy.maximum_bytes == len(content)
                                for policy, (_path, content, _mode) in zip(
                                    first.definition.expected_files,
                                    expected,
                                    strict=True,
                                )
                            )
                        )
                        self.assertIs(first.candidate_execution_authorized, False)
                        self.assertIs(first.model_selection_eligible, False)
                        self.assertIs(first.claim_authorized, False)
                        descriptors.append(first.descriptor)

        self.assertEqual(len(descriptors), 100)
        self.assertEqual(len({descriptor.fixture_id for descriptor in descriptors}), 100)
        self.assertEqual(
            len({descriptor.fixture_sha256 for descriptor in descriptors}), 100
        )

    def test_profiles_cover_ustar_edges_and_distinct_stop_conditions(self) -> None:
        task = task_by_parameters(
            self.tasks,
            selector="all-regular",
            conflict_policy="first-entry",
        )
        expected_stops = {
            "spaces-unicode": "invalid-checksum",
            "leading-dashes-globs": "invalid-header",
            "empty-duplicates": "truncated-header",
            "symlinks-ordering": "end-of-archive",
            "partial-permissions": "truncated-member",
        }
        rejected_types = {b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"x", b"g", b"L", b"K"}
        scans: dict[str, IndependentScan] = {}
        bundles = {}
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
            bundle = build_ustar_safe_extract_fixture_bundle(task, profile)
            scan = independently_scan_archive(archive_input(bundle).content)
            bundles[profile.profile_id] = bundle
            scans[profile.profile_id] = scan
            with self.subTest(profile=profile.profile_id):
                self.assertEqual(scan.stop_reason, expected_stops[profile.profile_id])
                self.assertTrue(rejected_types.issubset(set(scan.seen_typeflags)))
                self.assertIn(b"0", scan.seen_typeflags)
                self.assertIn(b"\0", scan.seen_typeflags)
                self.assertTrue(
                    {
                        "/absolute.txt",
                        "../parent.txt",
                        "unsafe/../parent.txt",
                        "unsafe/./dot.txt",
                        "unsafe//empty-component.txt",
                        "unsafe/new\nline.txt",
                        "unsafe/carriage\rreturn.txt",
                        "unsafe/tab\tname.txt",
                        "unsafe/delete\x7fname.txt",
                    }.issubset(
                        set(scan.unsafe_regular_names)
                    )
                )
                self.assertGreaterEqual(scan.invalid_text_regular_name_count, 2)
                names = {member.name for member in scan.regulars}
                self.assertIn("nul-type/accepted.txt", names)
                self.assertNotIn("after-invalid/hidden.txt", names)
                self.assertTrue(any(len(name.encode("utf-8")) > 100 for name in names))

        spaces_names = {member.name for member in scans["spaces-unicode"].regulars}
        self.assertTrue(any(" " in name for name in spaces_names))
        self.assertTrue(any("雪" in name or "é" in name for name in spaces_names))

        leading_names = {
            member.name for member in scans["leading-dashes-globs"].regulars
        }
        self.assertTrue(any(name.startswith("-") for name in leading_names))
        self.assertTrue(any(any(mark in name for mark in "*?[") for name in leading_names))

        empty_records = scans["empty-duplicates"].regulars
        self.assertTrue(any(not member.content for member in empty_records))
        self.assertLess(
            len({member.name for member in empty_records}), len(empty_records)
        )

        symlink_bundle = bundles["symlinks-ordering"]
        self.assertTrue(
            any(type(item) is InputSymlink for item in symlink_bundle.definition.inputs)
        )
        self.assertIs(type(symlink_bundle.definition.inputs[0]), InputSymlink)

        partial_archive = archive_input(bundles["partial-permissions"])
        self.assertEqual(partial_archive.mode, 0o400)

    def test_selectors_and_every_duplicate_policy_have_observable_effects(self) -> None:
        profile = profile_by_id("symlinks-ordering")
        policy_outputs: dict[str, dict[str, bytes]] = {}
        for conflict_policy in CONFLICT_POLICIES:
            task = task_by_parameters(
                self.tasks,
                selector="all-regular",
                conflict_policy=conflict_policy,
            )
            bundle = build_ustar_safe_extract_fixture_bundle(task, profile)
            policy_outputs[conflict_policy] = {
                output.path.removeprefix("output/extracted/"): output.content
                for output in bundle.oracle.outputs
            }

        self.assertNotIn("docs/readme.txt", policy_outputs["reject-duplicates"])
        self.assertNotIn("records/data.jsonl", policy_outputs["reject-duplicates"])
        self.assertTrue(
            policy_outputs["first-entry"]["docs/readme.txt"].startswith(
                b"last-readme"
            )
        )
        self.assertTrue(
            policy_outputs["last-entry"]["docs/readme.txt"].startswith(
                b"first-readme"
            )
        )
        self.assertNotIn("docs/readme.txt", policy_outputs["identical-only"])
        self.assertIn("records/data.jsonl", policy_outputs["identical-only"])
        readme_candidates = (
            policy_outputs["first-entry"]["docs/readme.txt"],
            policy_outputs["last-entry"]["docs/readme.txt"],
        )
        self.assertEqual(
            policy_outputs["smallest-sha256"]["docs/readme.txt"],
            min(readme_candidates, key=lambda content: sha256(content).hexdigest()),
        )

        selector_outputs: dict[str, tuple[tuple[str, bytes, int], ...]] = {}
        for selector in SELECTORS:
            task = task_by_parameters(
                self.tasks,
                selector=selector,
                conflict_policy="first-entry",
            )
            bundle = build_ustar_safe_extract_fixture_bundle(task, profile)
            selector_outputs[selector] = tuple(
                (output.path, output.content, output.mode)
                for output in bundle.oracle.outputs
            )
        self.assertTrue(
            all(
                PurePosixPath(path).name.endswith(".txt")
                for path, _content, _mode in selector_outputs["txt-suffix"]
            )
        )
        self.assertTrue(
            all(
                PurePosixPath(path).name.endswith(".jsonl")
                for path, _content, _mode in selector_outputs["jsonl-suffix"]
            )
        )
        self.assertTrue(
            all(content for _path, content, _mode in selector_outputs["nonempty-regular"])
        )
        self.assertTrue(
            any(not content for _path, content, _mode in selector_outputs["all-regular"])
        )

    def test_checksum_mutation_and_frozen_contract_bypasses_fail_closed(self) -> None:
        task = task_by_parameters(
            self.tasks,
            selector="txt-suffix",
            conflict_policy="smallest-sha256",
        )
        profile = profile_by_id("symlinks-ordering")
        pristine = build_ustar_safe_extract_fixture_bundle(task, profile)
        mutated_archive = bytearray(archive_input(pristine).content)
        mutated_archive[0] ^= 1
        mutated_scan = independently_scan_archive(bytes(mutated_archive))
        self.assertEqual(mutated_scan.stop_reason, "invalid-checksum")
        self.assertEqual(mutated_scan.regulars, ())

        with self.assertRaisesRegex(ExecutableFixtureUstarError, "task must"):
            build_ustar_safe_extract_fixture_bundle(  # type: ignore[arg-type]
                object(), profile
            )
        with self.assertRaisesRegex(ExecutableFixtureUstarError, "profile must"):
            build_ustar_safe_extract_fixture_bundle(  # type: ignore[arg-type]
                task, object()
            )

        forged_profile = exact_clone(profile)
        object.__setattr__(forged_profile, "profile_sha256", "0" * 64)
        with self.assertRaisesRegex(
            ExecutableFixtureUstarError, "closed-contract revalidation"
        ):
            build_ustar_safe_extract_fixture_bundle(task, forged_profile)

        forged_task = exact_clone(task)
        forged_parameters = UstarSafeExtractParameters(
            selector=task.parameters.selector,
            conflict_policy=task.parameters.conflict_policy,
        )
        object.__setattr__(forged_parameters, "selector", "regular-or-link")
        object.__setattr__(forged_task, "parameters", forged_parameters)
        with self.assertRaisesRegex(
            ExecutableFixtureUstarError, "closed-contract revalidation"
        ):
            build_ustar_safe_extract_fixture_bundle(forged_task, profile)

    def test_bundle_validation_rejects_oracle_and_archive_tampering(self) -> None:
        task = task_by_parameters(
            self.tasks,
            selector="jsonl-suffix",
            conflict_policy="identical-only",
        )
        profile = profile_by_id("empty-duplicates")

        oracle_tamper = build_ustar_safe_extract_fixture_bundle(task, profile)
        output = oracle_tamper.oracle.outputs[0]
        object.__setattr__(output, "content", output.content + b"tamper")
        with self.assertRaisesRegex(
            ExecutableFixtureBundleError, "oracle_sha256 does not match"
        ):
            validate_executable_fixture_bundle(oracle_tamper)

        archive_tamper = build_ustar_safe_extract_fixture_bundle(task, profile)
        archive = archive_input(archive_tamper)
        object.__setattr__(archive, "content", archive.content + b"tamper")
        with self.assertRaisesRegex(
            ExecutableFixtureBundleError,
            "fixture_definition_sha256 does not match",
        ):
            validate_executable_fixture_bundle(archive_tamper)


if __name__ == "__main__":
    unittest.main()
