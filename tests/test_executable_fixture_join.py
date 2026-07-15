from __future__ import annotations

from dataclasses import fields
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
    ExecutableFixtureBundleError,
    validate_executable_fixture_bundle,
)
from cbds.executable_fixture_join import (  # noqa: E402
    ExecutableFixtureJoinError,
    build_jsonl_keyed_inner_join_fixture_bundle,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
    ExecutableFixtureProfile,
)
from cbds.executable_fixture_verifier import (  # noqa: E402
    verify_executable_fixture,
)
from cbds.executable_static_second_registry import (  # noqa: E402
    build_jsonl_keyed_inner_join_tasks,
)
from cbds.executable_static_types import (  # noqa: E402
    ExecutableStaticTask,
    JsonlKeyedInnerJoinParameters,
)
from cbds.executable_workspace import (  # noqa: E402
    InputFile,
    InputSymlink,
    materialize_fixture,
)


KEYS = ("id", "key", "name", "slug")
POLICIES = (
    "cartesian",
    "first-left",
    "last-left",
    "first-right",
    "last-right",
)


class _Rejected(ValueError):
    pass


def profile_by_id(profile_id: str) -> ExecutableFixtureProfile:
    return next(
        profile
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        if profile.profile_id == profile_id
    )


def task_by_parameters(
    tasks: tuple[ExecutableStaticTask, ...], *, key: str, policy: str
) -> ExecutableStaticTask:
    matches = tuple(
        task
        for task in tasks
        if task.parameters.key == key
        and task.parameters.duplicate_policy == policy
    )
    if len(matches) != 1:
        raise AssertionError(f"expected one join task for {key=!r}, {policy=!r}")
    return matches[0]


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise _Rejected("duplicate member")
        result[name] = value
    return result


def _constant(_text: str) -> object:
    raise _Rejected("non-finite number")


def _float(_text: str) -> object:
    raise _Rejected("number is not a canonical integer")


def _integer(text: str) -> int:
    if len(text) > 17:
        raise _Rejected("integer outside safe range")
    value = int(text, 10)
    if str(value) != text or abs(value) > 9_007_199_254_740_991:
        raise _Rejected("integer is not canonical and safe")
    return value


def independent_records(content: bytes, key_name: str):
    records = []
    for line in content.split(b"\n"):
        if not line.strip():
            continue
        try:
            value = json.loads(
                line.decode("utf-8", errors="strict"),
                object_pairs_hook=_unique_object,
                parse_constant=_constant,
                parse_float=_float,
                parse_int=_integer,
            )
            if type(value) is not dict:
                continue
            selected = value.get(key_name)
            if type(selected) is not str or any(c in selected for c in "\0\r\n"):
                continue
            canonical(value)
        except (
            UnicodeDecodeError,
            UnicodeEncodeError,
            json.JSONDecodeError,
            _Rejected,
        ):
            continue
        records.append((len(records), selected, value))
    return records


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def independently_derive(task: ExecutableStaticTask, bundle: object) -> bytes:
    files = {
        item.path: item
        for item in bundle.definition.inputs
        if type(item) is InputFile
    }
    left = independent_records(files["input/left.jsonl"].content, task.parameters.key)
    right = independent_records(files["input/right.jsonl"].content, task.parameters.key)
    left_by_key: dict[str, list[tuple[int, str, dict[str, object]]]] = {}
    right_by_key: dict[str, list[tuple[int, str, dict[str, object]]]] = {}
    for record in left:
        left_by_key.setdefault(record[1], []).append(record)
    for record in right:
        right_by_key.setdefault(record[1], []).append(record)
    rows = []
    for key in set(left_by_key).intersection(right_by_key):
        left_group = left_by_key[key]
        right_group = right_by_key[key]
        policy = task.parameters.duplicate_policy
        if policy == "first-left":
            left_group = left_group[:1]
        elif policy == "last-left":
            left_group = left_group[-1:]
        elif policy == "first-right":
            right_group = right_group[:1]
        elif policy == "last-right":
            right_group = right_group[-1:]
        for left_record in left_group:
            for right_record in right_group:
                rows.append(
                    (
                        key.encode("utf-8"),
                        left_record[0],
                        right_record[0],
                        {
                            "key": key,
                            "left": left_record[2],
                            "right": right_record[2],
                        },
                    )
                )
    rows.sort(key=lambda row: row[:3])
    return b"" if not rows else b"\n".join(canonical(row[3]) for row in rows) + b"\n"


def oracle_content(bundle: object) -> bytes:
    outputs = bundle.oracle.outputs
    if len(outputs) != 1 or outputs[0].path != "output/joined.jsonl":
        raise AssertionError("join fixture output contract changed")
    return outputs[0].content


def decoded_rows(content: bytes) -> list[dict[str, object]]:
    if not content:
        return []
    if not content.endswith(b"\n"):
        raise AssertionError("nonempty JSONL lacks final LF")
    rows = []
    for line in content[:-1].split(b"\n"):
        value = json.loads(
            line.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_constant,
            parse_float=_float,
            parse_int=_integer,
        )
        if line != canonical(value):
            raise AssertionError("output row is not compact canonical JSON")
        if type(value) is not dict or set(value) != {"key", "left", "right"}:
            raise AssertionError("output row has extra or missing members")
        rows.append(value)
    return rows


def exact_clone(instance: object):
    clone = object.__new__(type(instance))
    for field in fields(instance):
        object.__setattr__(clone, field.name, getattr(instance, field.name))
    return clone


def write_oracle(workspace: Path, bundle: object) -> None:
    output = bundle.oracle.outputs[0]
    target = workspace / output.path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.parent.chmod(0o755)
    target.write_bytes(output.content)
    target.chmod(output.mode)


class JsonlKeyedInnerJoinFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = build_jsonl_keyed_inner_join_tasks()

    def test_all_20_by_5_are_independent_exact_deterministic_and_nonexecuting(
        self,
    ) -> None:
        self.assertEqual(len(self.tasks), 20)
        self.assertEqual(
            {
                (task.parameters.key, task.parameters.duplicate_policy)
                for task in self.tasks
            },
            {(key, policy) for key in KEYS for policy in POLICIES},
        )
        descriptors = []
        with mock.patch.object(
            subprocess, "run", side_effect=AssertionError("subprocess.run executed")
        ), mock.patch.object(
            subprocess, "Popen", side_effect=AssertionError("Popen executed")
        ), mock.patch.object(
            os, "system", side_effect=AssertionError("os.system executed")
        ), mock.patch.object(
            os, "popen", side_effect=AssertionError("os.popen executed")
        ):
            for task in self.tasks:
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                    with self.subTest(
                        key=task.parameters.key,
                        policy=task.parameters.duplicate_policy,
                        profile=profile.profile_id,
                    ):
                        first = build_jsonl_keyed_inner_join_fixture_bundle(task, profile)
                        second = build_jsonl_keyed_inner_join_fixture_bundle(task, profile)
                        self.assertEqual(first, second)
                        validate_executable_fixture_bundle(first)
                        self.assertEqual(oracle_content(first), independently_derive(task, first))
                        self.assertEqual(first.task_contract_sha256, task.task_contract_sha256)
                        self.assertEqual(first.profile_sha256, profile.profile_sha256)
                        self.assertEqual(
                            first.oracle.semantic_verifier_identity,
                            "verify-jsonl-keyed-inner-join-v1",
                        )
                        output = first.oracle.outputs[0]
                        self.assertEqual(output.mode, 0o644)
                        expected = first.definition.expected_files
                        self.assertEqual(len(expected), 1)
                        self.assertEqual(expected[0].path, "output/joined.jsonl")
                        self.assertEqual(expected[0].mode, 0o644)
                        self.assertGreaterEqual(expected[0].maximum_bytes, len(output.content))
                        self.assertIs(first.candidate_execution_authorized, False)
                        self.assertIs(first.model_selection_eligible, False)
                        self.assertIs(first.claim_authorized, False)
                        decoded_rows(output.content)
                        descriptors.append(first.descriptor)
        self.assertEqual(len(descriptors), 100)
        self.assertEqual(len({item.fixture_id for item in descriptors}), 100)
        self.assertEqual(len({item.fixture_sha256 for item in descriptors}), 100)

    def test_profiles_cover_required_edges_and_required_streams_stay_readable(self) -> None:
        task = task_by_parameters(self.tasks, key="slug", policy="cartesian")
        bundles = {
            profile.profile_id: build_jsonl_keyed_inner_join_fixture_bundle(task, profile)
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        }
        for profile_id, bundle in bundles.items():
            required = {
                item.path: item
                for item in bundle.definition.inputs
                if type(item) is InputFile
                and item.path in {"input/left.jsonl", "input/right.jsonl"}
            }
            self.assertEqual(set(required), {"input/left.jsonl", "input/right.jsonl"})
            self.assertTrue(all(item.mode & 0o444 for item in required.values()))
            self.assertEqual(oracle_content(bundle), independently_derive(task, bundle))

        unicode_bytes = b"".join(
            item.content
            for item in bundles["spaces-unicode"].definition.inputs
            if type(item) is InputFile
        )
        self.assertIn("한글".encode(), unicode_bytes)
        self.assertIn(b"space key", unicode_bytes)
        self.assertIn(b'"nested"', unicode_bytes)

        glob_bytes = b"".join(
            item.content
            for item in bundles["leading-dashes-globs"].definition.inputs
            if type(item) is InputFile
        )
        self.assertIn(b"-leading", glob_bytes)
        self.assertIn(b"glob[*]?", glob_bytes)
        glob_lines = oracle_content(bundles["leading-dashes-globs"]).splitlines()
        self.assertLess(len(set(glob_lines)), len(glob_lines))

        empty = bundles["empty-duplicates"]
        self.assertEqual(oracle_content(empty), b"")
        empty_inputs = [item for item in empty.definition.inputs if type(item) is InputFile]
        self.assertTrue(all(item.content.startswith(b"\n") for item in empty_inputs))
        self.assertTrue(all(len(independent_records(item.content, "slug")) == 2 for item in empty_inputs))

        ordering = bundles["symlinks-ordering"]
        self.assertEqual(
            [item.path for item in ordering.definition.inputs],
            [
                "input/right.jsonl",
                "input/ignored-left-link.jsonl",
                "input/left.jsonl",
            ],
        )
        self.assertEqual(
            len([item for item in ordering.definition.inputs if type(item) is InputSymlink]),
            1,
        )
        ordering_keys = [row["key"] for row in decoded_rows(oracle_content(ordering))]
        self.assertEqual(ordering_keys, sorted(ordering_keys, key=str.encode))
        self.assertEqual(ordering_keys[0], "a-first")

        partial = bundles["partial-permissions"]
        partial_inputs = [item for item in partial.definition.inputs if type(item) is InputFile]
        self.assertEqual({item.mode for item in partial_inputs}, {0o000, 0o400, 0o444})
        required_partial = {
            item.path: item.mode
            for item in partial_inputs
            if item.path in {"input/left.jsonl", "input/right.jsonl"}
        }
        self.assertEqual(required_partial, {"input/left.jsonl": 0o400, "input/right.jsonl": 0o444})
        self.assertTrue(any(b"NaN" in item.content and b"\xff" in item.content for item in partial_inputs))
        partial_rows = decoded_rows(oracle_content(partial))
        self.assertEqual(len(partial_rows), 5)
        self.assertEqual({row["key"] for row in partial_rows}, {"other", "shared"})

    def test_duplicate_policies_select_the_declared_accepted_records(self) -> None:
        profile = profile_by_id("spaces-unicode")
        expected_pairs = {
            "cartesian": [
                ("left-0", "right-0"),
                ("left-0", "right-1"),
                ("left-2", "right-0"),
                ("left-2", "right-1"),
                ("left-1", "right-2"),
            ],
            "first-left": [
                ("left-0", "right-0"),
                ("left-0", "right-1"),
                ("left-1", "right-2"),
            ],
            "last-left": [
                ("left-2", "right-0"),
                ("left-2", "right-1"),
                ("left-1", "right-2"),
            ],
            "first-right": [
                ("left-0", "right-0"),
                ("left-2", "right-0"),
                ("left-1", "right-2"),
            ],
            "last-right": [
                ("left-0", "right-1"),
                ("left-2", "right-1"),
                ("left-1", "right-2"),
            ],
        }
        # Compare as multisets because canonical key-byte ordering puts the
        # Unicode join key after the ASCII key independently of input order.
        for policy, expected in expected_pairs.items():
            task = task_by_parameters(self.tasks, key="id", policy=policy)
            bundle = build_jsonl_keyed_inner_join_fixture_bundle(task, profile)
            observed = [
                (row["left"]["side"], row["right"]["side"])
                for row in decoded_rows(oracle_content(bundle))
            ]
            self.assertCountEqual(observed, expected)

    def test_materialized_oracle_passes_and_mutations_fail_closed(self) -> None:
        task = task_by_parameters(self.tasks, key="name", policy="cartesian")
        profile = profile_by_id("spaces-unicode")
        bundle = build_jsonl_keyed_inner_join_fixture_bundle(task, profile)
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "join"
            with materialize_fixture(bundle.definition, workspace) as handle:
                write_oracle(workspace, bundle)
                self.assertTrue(verify_executable_fixture(bundle, handle).passed)

                rows = decoded_rows(oracle_content(bundle))
                equivalent = (
                    b"\n".join(
                        json.dumps(
                            dict(reversed(tuple(row.items()))),
                            ensure_ascii=True,
                            allow_nan=False,
                            separators=(", ", ": "),
                        ).encode("utf-8")
                        for row in rows
                    )
                    + b"\n"
                )
                self.assertGreater(len(equivalent), len(oracle_content(bundle)))
                target = workspace / "output/joined.jsonl"
                target.write_bytes(equivalent)
                target.chmod(0o644)
                self.assertTrue(verify_executable_fixture(bundle, handle).passed)

                rows[0]["right"]["mutation"] = True
                changed = b"\n".join(canonical(row) for row in rows) + b"\n"
                target.write_bytes(changed)
                target.chmod(0o644)
                evidence = verify_executable_fixture(bundle, handle)
                self.assertFalse(evidence.passed)
                self.assertEqual(evidence.failure_code, "semantic-mismatch")

                target.write_bytes(b'{ "key":"x","left":{},"right":{} }\n')
                target.chmod(0o644)
                malformed = verify_executable_fixture(bundle, handle)
                self.assertFalse(malformed.passed)
                self.assertEqual(malformed.failure_code, "malformed-semantic-output")

        empty_task = task_by_parameters(self.tasks, key="name", policy="last-left")
        empty_bundle = build_jsonl_keyed_inner_join_fixture_bundle(
            empty_task, profile_by_id("empty-duplicates")
        )
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "empty-join"
            with materialize_fixture(empty_bundle.definition, workspace) as handle:
                write_oracle(workspace, empty_bundle)
                self.assertTrue(verify_executable_fixture(empty_bundle, handle).passed)

    def test_revalidation_and_content_bindings_reject_frozen_bypasses(self) -> None:
        task = task_by_parameters(self.tasks, key="key", policy="last-right")
        profile = profile_by_id("partial-permissions")
        with self.assertRaisesRegex(ExecutableFixtureJoinError, "task must"):
            build_jsonl_keyed_inner_join_fixture_bundle(object(), profile)  # type: ignore[arg-type]
        with self.assertRaisesRegex(ExecutableFixtureJoinError, "profile must"):
            build_jsonl_keyed_inner_join_fixture_bundle(task, object())  # type: ignore[arg-type]

        forged_profile = exact_clone(profile)
        object.__setattr__(forged_profile, "profile_sha256", "0" * 64)
        with self.assertRaisesRegex(ExecutableFixtureJoinError, "closed-contract"):
            build_jsonl_keyed_inner_join_fixture_bundle(task, forged_profile)

        forged_task = exact_clone(task)
        forged_parameters = JsonlKeyedInnerJoinParameters(
            key=task.parameters.key,
            duplicate_policy=task.parameters.duplicate_policy,
        )
        object.__setattr__(forged_parameters, "duplicate_policy", "deduplicate")
        object.__setattr__(forged_task, "parameters", forged_parameters)
        with self.assertRaisesRegex(ExecutableFixtureJoinError, "closed-contract"):
            build_jsonl_keyed_inner_join_fixture_bundle(forged_task, profile)

        oracle_tamper = build_jsonl_keyed_inner_join_fixture_bundle(task, profile)
        output = oracle_tamper.oracle.outputs[0]
        object.__setattr__(output, "content", output.content + b"tamper")
        with self.assertRaisesRegex(
            ExecutableFixtureBundleError, "oracle_sha256 does not match"
        ):
            validate_executable_fixture_bundle(oracle_tamper)

        input_tamper = build_jsonl_keyed_inner_join_fixture_bundle(task, profile)
        source = next(
            item for item in input_tamper.definition.inputs if type(item) is InputFile
        )
        object.__setattr__(source, "content", source.content + b"tamper")
        with self.assertRaisesRegex(
            ExecutableFixtureBundleError, "fixture_definition_sha256 does not match"
        ):
            validate_executable_fixture_bundle(input_tamper)


if __name__ == "__main__":
    unittest.main()
