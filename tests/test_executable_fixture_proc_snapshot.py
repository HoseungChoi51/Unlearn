from __future__ import annotations

from dataclasses import fields
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds import executable_fixture_proc_snapshot as proc_fixture  # noqa: E402
from cbds.executable_fixture_bundle import (  # noqa: E402
    ExecutableFixtureBundleError,
    validate_executable_fixture_bundle,
)
from cbds.executable_fixture_proc_snapshot import (  # noqa: E402
    OUTPUT_MAXIMUM_BYTES,
    ExecutableFixtureProcSnapshotError,
    build_proc_snapshot_report_fixture_bundle,
)
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
    ExecutableFixtureProfile,
)
from cbds.executable_fixture_verifier import (  # noqa: E402
    verify_executable_fixture,
)
from cbds.executable_static_second_registry import (  # noqa: E402
    build_proc_snapshot_report_tasks,
)
from cbds.executable_static_types import (  # noqa: E402
    ExecutableStaticTask,
    ProcSnapshotReportParameters,
)
from cbds.executable_workspace import (  # noqa: E402
    InputFile,
    InputSymlink,
    materialize_fixture,
)


VIEWS = ("identity", "ownership", "memory", "command")
PREDICATES = (
    "all-valid",
    "running-only",
    "non-zombie",
    "uid-zero",
    "has-argv",
)
STATUS_KEYS = {"pid", "ppid", "uid", "rss_kib", "state", "comm"}
STATES = {"R", "S", "D", "Z", "T", "I"}


def profile_by_id(profile_id: str) -> ExecutableFixtureProfile:
    matches = tuple(
        profile
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        if profile.profile_id == profile_id
    )
    if len(matches) != 1:
        raise AssertionError(f"expected one fixture profile for {profile_id!r}")
    return matches[0]


def task_by_parameters(
    tasks: tuple[ExecutableStaticTask, ...], *, view: str, predicate: str
) -> ExecutableStaticTask:
    matches = tuple(
        task
        for task in tasks
        if task.parameters.view == view and task.parameters.predicate == predicate
    )
    if len(matches) != 1:
        raise AssertionError(
            f"expected one process task for {view=!r}, {predicate=!r}"
        )
    return matches[0]


def _independent_no_duplicate_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> object:
    raise ValueError("non-finite JSON")


def _reject_float(_value: str) -> object:
    raise ValueError("status number is not a canonical integer")


def _safe_integer(value: str) -> int:
    if len(value) > 17:
        raise ValueError("status integer exceeds its parser bound")
    parsed = int(value, 10)
    if str(parsed) != value or not 0 <= parsed <= 9_007_199_254_740_991:
        raise ValueError("status integer is not canonical and safe")
    return parsed


def independent_status(content: bytes, directory_pid: int) -> dict[str, object] | None:
    try:
        value = json.loads(
            content.decode("utf-8", errors="strict"),
            object_pairs_hook=_independent_no_duplicate_object,
            parse_constant=_reject_nonfinite,
            parse_float=_reject_float,
            parse_int=_safe_integer,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        return None
    if type(value) is not dict or set(value) != STATUS_KEYS:
        return None
    if any(
        type(value.get(field)) is not int or value[field] < 0
        for field in ("pid", "ppid", "uid", "rss_kib")
    ):
        return None
    if value["pid"] != directory_pid:
        return None
    if type(value.get("state")) is not str or value["state"] not in STATES:
        return None
    comm = value.get("comm")
    if type(comm) is not str or any(character in comm for character in "\0\r\n"):
        return None
    try:
        comm.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return None
    return value


def independent_cmdline(item: InputFile | InputSymlink | None) -> tuple[str, ...]:
    if type(item) is not InputFile or item.mode & 0o444 == 0:
        return ()
    if not item.content or item.content[-1:] != b"\0":
        return ()
    pieces = item.content[:-1].split(b"\0")
    if not pieces or any(piece == b"" for piece in pieces):
        return ()
    try:
        return tuple(piece.decode("utf-8", errors="strict") for piece in pieces)
    except UnicodeDecodeError:
        return ()


def independent_predicate(
    status: dict[str, object], argv: tuple[str, ...], predicate: str
) -> bool:
    rules = {
        "all-valid": True,
        "running-only": status["state"] == "R",
        "non-zombie": status["state"] != "Z",
        "uid-zero": status["uid"] == 0,
        "has-argv": len(argv) > 0,
    }
    return rules[predicate]


def independent_projection(
    status: dict[str, object], argv: tuple[str, ...], view: str
) -> dict[str, object]:
    if view == "identity":
        return {
            "pid": status["pid"],
            "ppid": status["ppid"],
            "state": status["state"],
        }
    if view == "ownership":
        return {"pid": status["pid"], "uid": status["uid"]}
    if view == "memory":
        return {"pid": status["pid"], "rss_kib": status["rss_kib"]}
    if view == "command":
        return {
            "pid": status["pid"],
            "comm": status["comm"],
            "argv": list(argv),
        }
    raise AssertionError(f"unknown process view: {view!r}")


def independently_derive_content(
    task: ExecutableStaticTask, bundle: object
) -> bytes:
    entries = {item.path: item for item in bundle.definition.inputs}
    selected: list[tuple[int, dict[str, object]]] = []
    for item in bundle.definition.inputs:
        if type(item) is not InputFile or item.mode & 0o444 == 0:
            continue
        path = PurePosixPath(item.path)
        if (
            len(path.parts) != 4
            or path.parts[:2] != ("input", "proc-snapshot")
            or path.name != "status.json"
        ):
            continue
        pid_text = path.parts[2]
        if (
            not pid_text
            or pid_text[0] not in "123456789"
            or any(character not in "0123456789" for character in pid_text)
        ):
            continue
        pid = int(pid_text)
        status = independent_status(item.content, pid)
        if status is None:
            continue
        argv = independent_cmdline(
            entries.get((path.parent / "cmdline.bin").as_posix())
        )
        if independent_predicate(status, argv, task.parameters.predicate):
            selected.append(
                (
                    pid,
                    independent_projection(status, argv, task.parameters.view),
                )
            )
    selected.sort(key=lambda row: row[0])
    return b"".join(
        json.dumps(
            row,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
        for _pid, row in selected
    )


def parse_output_rows(content: bytes) -> list[dict[str, object]]:
    if not content:
        return []
    return [json.loads(line) for line in content.splitlines()]


def exact_clone(instance: object):
    clone = object.__new__(type(instance))
    for field in fields(instance):
        object.__setattr__(clone, field.name, getattr(instance, field.name))
    return clone


def write_oracle_output(
    bundle: object, workspace: Path, content: bytes | None = None
) -> None:
    output = bundle.oracle.outputs[0]
    target = workspace / output.path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.parent.chmod(0o755)
    target.write_bytes(output.content if content is None else content)
    target.chmod(0o644)


class ProcSnapshotReportFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = build_proc_snapshot_report_tasks()

    def test_all_20_by_5_bundles_match_an_independent_oracle_without_execution(
        self,
    ) -> None:
        self.assertEqual(len(self.tasks), 20)
        self.assertEqual(
            {
                (task.parameters.view, task.parameters.predicate)
                for task in self.tasks
            },
            {(view, predicate) for view in VIEWS for predicate in PREDICATES},
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
            for task in self.tasks:
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                    with self.subTest(
                        view=task.parameters.view,
                        predicate=task.parameters.predicate,
                        profile=profile.profile_id,
                    ):
                        first = build_proc_snapshot_report_fixture_bundle(task, profile)
                        second = build_proc_snapshot_report_fixture_bundle(
                            task, profile
                        )
                        self.assertEqual(first, second)
                        validate_executable_fixture_bundle(first)
                        self.assertEqual(
                            first.task_contract_sha256,
                            task.task_contract_sha256,
                        )
                        self.assertEqual(first.profile_sha256, profile.profile_sha256)
                        self.assertEqual(
                            first.oracle.semantic_verifier_identity,
                            "verify-proc-snapshot-report-v1",
                        )
                        self.assertEqual(len(first.oracle.outputs), 1)
                        output = first.oracle.outputs[0]
                        self.assertEqual(output.path, "output/processes.jsonl")
                        self.assertEqual(output.mode, 0o644)
                        self.assertEqual(
                            output.content,
                            independently_derive_content(task, first),
                        )
                        # Every task/profile grid case includes the valid anchor.
                        self.assertNotEqual(output.content, b"")
                        self.assertTrue(output.content.endswith(b"\n"))
                        pids = [row["pid"] for row in parse_output_rows(output.content)]
                        self.assertEqual(pids, sorted(pids))
                        self.assertEqual(len(pids), len(set(pids)))
                        policy = first.definition.expected_files
                        self.assertEqual(len(policy), 1)
                        self.assertEqual(policy[0].path, output.path)
                        self.assertEqual(policy[0].mode, output.mode)
                        self.assertEqual(
                            policy[0].maximum_bytes,
                            OUTPUT_MAXIMUM_BYTES,
                        )
                        self.assertIs(first.candidate_execution_authorized, False)
                        self.assertIs(first.model_selection_eligible, False)
                        self.assertIs(first.claim_authorized, False)
                        descriptors.append(first.descriptor)

        self.assertEqual(len(descriptors), 100)
        self.assertEqual(
            len({descriptor.fixture_id for descriptor in descriptors}), 100
        )

    def test_profiles_cover_the_closed_process_snapshot_edge_cases(self) -> None:
        command_task = task_by_parameters(
            self.tasks, view="command", predicate="all-valid"
        )

        spaces = build_proc_snapshot_report_fixture_bundle(
            command_task, profile_by_id("spaces-unicode")
        )
        space_rows = parse_output_rows(spaces.oracle.outputs[0].content)
        self.assertTrue(any(" " in row["comm"] for row in space_rows))
        self.assertTrue(
            any(
                any(ord(character) > 127 for character in row["comm"])
                for row in space_rows
            )
        )
        self.assertTrue(
            any(
                any(
                    " " in argument
                    or any(ord(character) > 127 for character in argument)
                    for argument in row["argv"]
                )
                for row in space_rows
            )
        )

        leading = build_proc_snapshot_report_fixture_bundle(
            command_task, profile_by_id("leading-dashes-globs")
        )
        leading_argv = [
            argument
            for row in parse_output_rows(leading.oracle.outputs[0].content)
            for argument in row["argv"]
        ]
        self.assertTrue(any(argument.startswith("-") for argument in leading_argv))
        self.assertTrue(
            any(any(mark in argument for mark in "*?[") for argument in leading_argv)
        )

        empty = build_proc_snapshot_report_fixture_bundle(
            command_task, profile_by_id("empty-duplicates")
        )
        empty_rows = {
            row["pid"]: row
            for row in parse_output_rows(empty.oracle.outputs[0].content)
        }
        self.assertEqual(empty_rows[1]["argv"], ["duplicate", "duplicate", "--same"])
        self.assertEqual(
            {pid for pid, row in empty_rows.items() if row["argv"] == []},
            {4, 8, 12, 13, 16},
        )

        ordering = build_proc_snapshot_report_fixture_bundle(
            command_task, profile_by_id("symlinks-ordering")
        )
        input_paths = [item.path for item in ordering.definition.inputs]
        self.assertNotEqual(input_paths, sorted(input_paths, key=str.encode))
        self.assertTrue(
            any(type(item) is InputSymlink for item in ordering.definition.inputs)
        )
        self.assertTrue(
            any(
                type(item) is InputSymlink
                and item.path.endswith("/30/status.json")
                for item in ordering.definition.inputs
            )
        )
        self.assertTrue(
            any(
                type(item) is InputSymlink
                and item.path.endswith("/40/cmdline.bin")
                for item in ordering.definition.inputs
            )
        )
        self.assertEqual(
            [
                row["pid"]
                for row in parse_output_rows(ordering.oracle.outputs[0].content)
            ],
            [2, 10, 40, 100],
        )
        ordering_rows = {
            row["pid"]: row
            for row in parse_output_rows(ordering.oracle.outputs[0].content)
        }
        self.assertNotIn(30, ordering_rows)
        self.assertEqual(ordering_rows[40]["argv"], [])

        partial = build_proc_snapshot_report_fixture_bundle(
            command_task, profile_by_id("partial-permissions")
        )
        self.assertTrue(
            any(
                type(item) is InputFile
                and item.path.endswith("/status.json")
                and item.mode == 0
                for item in partial.definition.inputs
            )
        )
        self.assertTrue(
            any(
                type(item) is InputFile
                and item.path.endswith("/cmdline.bin")
                and item.mode == 0
                for item in partial.definition.inputs
            )
        )
        self.assertTrue(
            any(
                type(item) is InputFile
                and item.path.endswith("/cmdline.bin")
                and not any(
                    type(candidate) is InputFile
                    and candidate.path
                    == (PurePosixPath(item.path).parent / "status.json").as_posix()
                    for candidate in partial.definition.inputs
                )
                for item in partial.definition.inputs
            )
        )
        status_payloads = [
            item.content
            for item in partial.definition.inputs
            if type(item) is InputFile and item.path.endswith("/status.json")
        ]
        self.assertTrue(any(b'"pid":17,"pid":17' in item for item in status_payloads))
        self.assertTrue(any(b'"rss_kib":NaN' in item for item in status_payloads))
        self.assertTrue(any(b'"extra":0' in item for item in status_payloads))
        self.assertTrue(any(b'"ppid":-1' in item for item in status_payloads))
        self.assertEqual(
            [
                row["pid"]
                for row in parse_output_rows(partial.oracle.outputs[0].content)
            ],
            [6, 19, 21],
        )
        has_argv = build_proc_snapshot_report_fixture_bundle(
            task_by_parameters(self.tasks, view="command", predicate="has-argv"),
            profile_by_id("partial-permissions"),
        )
        self.assertEqual(
            [
                row["pid"]
                for row in parse_output_rows(has_argv.oracle.outputs[0].content)
            ],
            [6],
        )

    def test_all_bundles_materialize_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for task_index, task in enumerate(self.tasks):
                for profile_index, profile in enumerate(
                    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
                ):
                    bundle = build_proc_snapshot_report_fixture_bundle(
                        task, profile
                    )
                    with self.subTest(
                        view=task.parameters.view,
                        predicate=task.parameters.predicate,
                        profile=profile.profile_id,
                    ):
                        with materialize_fixture(
                            bundle.definition,
                            root / f"case-{task_index}-{profile_index}",
                        ) as handle:
                            write_oracle_output(bundle, handle.workspace)
                            evidence = verify_executable_fixture(bundle, handle)
                            self.assertTrue(evidence.passed)
                            self.assertIsNone(evidence.failure_code)
                            self.assertEqual(len(evidence.outputs), 1)

    def test_materialized_verifier_rejects_malformed_jsonl(self) -> None:
        identity = build_proc_snapshot_report_fixture_bundle(
            task_by_parameters(
                self.tasks, view="identity", predicate="all-valid"
            ),
            profile_by_id("symlinks-ordering"),
        )
        identity_malformed = (
            b'{"pid":2,"pid":2,"ppid":0,"state":"Z"}\n',
            (
                b'{"pid":10,"ppid":2,"state":"R"}\n'
                b'{"pid":2,"ppid":0,"state":"Z"}\n'
            ),
            b'{"pid":true,"ppid":0,"state":"Z"}\n',
            b'{"pid":2,"ppid":0,"state":"Z"}',
        )
        command = build_proc_snapshot_report_fixture_bundle(
            task_by_parameters(
                self.tasks, view="command", predicate="all-valid"
            ),
            profile_by_id("symlinks-ordering"),
        )
        cases = tuple((identity, payload) for payload in identity_malformed) + (
            (command, b'{"argv":[""],"comm":"two","pid":2}\n'),
        )
        for bundle, payload in cases:
            with self.subTest(
                payload=payload
            ), tempfile.TemporaryDirectory() as temporary:
                with materialize_fixture(
                    bundle.definition, Path(temporary) / "workspace"
                ) as handle:
                    write_oracle_output(bundle, handle.workspace, payload)
                    evidence = verify_executable_fixture(bundle, handle)
                    self.assertFalse(evidence.passed)
                    self.assertEqual(
                        evidence.failure_code,
                        "malformed-semantic-output",
                    )

    def test_materialized_verifier_accepts_longer_equivalent_json(self) -> None:
        bundle = build_proc_snapshot_report_fixture_bundle(
            task_by_parameters(
                self.tasks, view="command", predicate="all-valid"
            ),
            profile_by_id("spaces-unicode"),
        )
        oracle = bundle.oracle.outputs[0].content
        rows = parse_output_rows(oracle)
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
        self.assertGreater(len(equivalent), len(oracle))
        self.assertLessEqual(
            len(equivalent),
            bundle.definition.expected_files[0].maximum_bytes,
        )
        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(
                bundle.definition, Path(temporary) / "workspace"
            ) as handle:
                write_oracle_output(bundle, handle.workspace, equivalent)
                self.assertTrue(verify_executable_fixture(bundle, handle).passed)

    def test_rejects_wrong_types_and_frozen_object_bypasses(self) -> None:
        task = task_by_parameters(
            self.tasks, view="command", predicate="uid-zero"
        )
        profile = profile_by_id("spaces-unicode")
        with self.assertRaisesRegex(ExecutableFixtureProcSnapshotError, "task must"):
            build_proc_snapshot_report_fixture_bundle(  # type: ignore[arg-type]
                object(), profile
            )
        with self.assertRaisesRegex(ExecutableFixtureProcSnapshotError, "profile must"):
            build_proc_snapshot_report_fixture_bundle(  # type: ignore[arg-type]
                task, object()
            )

        forged_profile = exact_clone(profile)
        object.__setattr__(forged_profile, "profile_sha256", "0" * 64)
        with self.assertRaisesRegex(
            ExecutableFixtureProcSnapshotError, "closed-contract revalidation"
        ):
            build_proc_snapshot_report_fixture_bundle(task, forged_profile)

        forged_task = exact_clone(task)
        forged_parameters = ProcSnapshotReportParameters(
            view=task.parameters.view,
            predicate=task.parameters.predicate,
        )
        object.__setattr__(forged_parameters, "predicate", "kernel-only")
        object.__setattr__(forged_task, "parameters", forged_parameters)
        with self.assertRaisesRegex(
            ExecutableFixtureProcSnapshotError, "closed-contract revalidation"
        ):
            build_proc_snapshot_report_fixture_bundle(forged_task, profile)

    def test_bundle_validation_rejects_oracle_and_input_tampering(self) -> None:
        task = task_by_parameters(
            self.tasks, view="memory", predicate="non-zombie"
        )
        profile = profile_by_id("partial-permissions")

        oracle_tamper = build_proc_snapshot_report_fixture_bundle(task, profile)
        output = oracle_tamper.oracle.outputs[0]
        object.__setattr__(output, "content", output.content + b"tamper")
        with self.assertRaisesRegex(
            ExecutableFixtureBundleError, "oracle_sha256 does not match"
        ):
            validate_executable_fixture_bundle(oracle_tamper)

        input_tamper = build_proc_snapshot_report_fixture_bundle(task, profile)
        status = next(
            item
            for item in input_tamper.definition.inputs
            if type(item) is InputFile and item.path.endswith("/status.json")
        )
        object.__setattr__(status, "content", status.content + b"tamper")
        with self.assertRaisesRegex(
            ExecutableFixtureBundleError,
            "fixture_definition_sha256 does not match",
        ):
            validate_executable_fixture_bundle(input_tamper)

    def test_zero_process_output_is_a_valid_zero_byte_file(self) -> None:
        task = task_by_parameters(
            self.tasks, view="command", predicate="has-argv"
        )
        profile = profile_by_id("partial-permissions")
        no_status = (
            InputFile(
                "input/proc-snapshot/9/cmdline.bin",
                b"orphan\0",
                0o444,
            ),
        )
        with mock.patch.object(proc_fixture, "_fixture_inputs", return_value=no_status):
            bundle = build_proc_snapshot_report_fixture_bundle(task, profile)
        validate_executable_fixture_bundle(bundle)
        self.assertEqual(bundle.oracle.outputs[0].content, b"")
        self.assertEqual(
            bundle.definition.expected_files[0].maximum_bytes,
            OUTPUT_MAXIMUM_BYTES,
        )

        with tempfile.TemporaryDirectory() as temporary:
            with materialize_fixture(
                bundle.definition, Path(temporary) / "workspace"
            ) as handle:
                write_oracle_output(bundle, handle.workspace)
                evidence = verify_executable_fixture(bundle, handle)
                self.assertTrue(evidence.passed)


if __name__ == "__main__":
    unittest.main()
