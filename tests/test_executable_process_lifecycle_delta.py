from __future__ import annotations

import ast
import copy
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_process_lifecycle_delta as lifecycle  # noqa: E402
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_process_lifecycle_delta import (  # noqa: E402
    PROCESS_LIFECYCLE_DELTA_ALLOWED_TOOLS,
    PROCESS_LIFECYCLE_DELTA_ATOMICITY_OBSERVED,
    PROCESS_LIFECYCLE_DELTA_CANDIDATE_EXIT_STATUS_OBSERVED,
    PROCESS_LIFECYCLE_DELTA_FAMILY_ID,
    PROCESS_LIFECYCLE_DELTA_FINAL_OUTPUT_OBSERVED,
    PROCESS_LIFECYCLE_DELTA_INPUT_PRESERVATION_OBSERVED,
    PROCESS_LIFECYCLE_DELTA_LIVE_PROC_OBSERVED,
    PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER,
    PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
    PROCESS_LIFECYCLE_DELTA_OUTPUT,
    PROCESS_LIFECYCLE_DELTA_OUTPUT_MAXIMUM_BYTES,
    PROCESS_LIFECYCLE_DELTA_PROCESS_ACTIONS_OBSERVED,
    PROCESS_LIFECYCLE_DELTA_PROOF_CHANGED_OUTPUT_BYTES,
    PROCESS_LIFECYCLE_DELTA_PROOF_DISJOINT_OUTPUT_BYTES,
    PROCESS_LIFECYCLE_DELTA_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES,
    PROCESS_LIFECYCLE_DELTA_READ_SCOPE_OBSERVED,
    PROCESS_LIFECYCLE_DELTA_SELECTION_POLICIES,
    PROCESS_LIFECYCLE_DELTA_SNAPSHOT_PAIRS,
    PROCESS_LIFECYCLE_DELTA_TOOL_HISTORY_OBSERVED,
    PROCESS_LIFECYCLE_DELTA_TRANSIENT_STATE_OBSERVED,
    PROCESS_LIFECYCLE_DELTA_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
    PROCESS_LIFECYCLE_DELTA_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE,
    ProcessLifecycleDeltaError,
    ProcessLifecycleDeltaParameters,
    ProcessPairMetadata,
    build_process_lifecycle_delta_fixture_bundle,
    build_process_lifecycle_delta_tasks,
    compute_process_lifecycle_delta_discrimination_sha256,
    compute_process_lifecycle_delta_proved_output_bound,
    derive_process_lifecycle_delta_state,
    materialize_process_lifecycle_delta_fixture,
    parse_process_lifecycle_delta_output,
    reference_process_lifecycle_delta_state,
    validate_process_lifecycle_delta_fixture_bundle,
    validate_process_lifecycle_delta_fixture_for_task_profile,
    verify_process_lifecycle_delta_fixture_bundle,
    verify_process_lifecycle_delta_fixture_for_task_profile,
    verify_process_lifecycle_delta_workspace,
)
from cbds.executable_static_types import OpaqueFixtureDescriptor  # noqa: E402
from cbds.executable_workspace import (  # noqa: E402
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputHardlink,
    InputSymlink,
    MAX_TOTAL_BYTES,
)


TASKS = build_process_lifecycle_delta_tasks()
TASK_BY_CELL = {
    (
        task.parameters.snapshot_pair,
        task.parameters.selection_policy,
    ): task
    for task in TASKS
}
PROFILE_BY_ID = {
    profile.profile_id: profile
    for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
}
EXPECTED_DISCRIMINATION_SHA256 = (
    "1a94ccdd0d75698973f172daa5a90e660747718969b05f0d6b414ac934c7e383"
)
BOOT_ID = "01234567-89ab-cdef-0123-456789abcdef"


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _pair(
    *,
    before_ticks: int = 1_000,
    after_ticks: int = 2_000,
    rss_threshold: int = 4_096,
    cpu_threshold: int = 50_000,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "before": {
            "boot_id": BOOT_ID,
            "snapshot_ticks": before_ticks,
        },
        "after": {
            "boot_id": BOOT_ID,
            "snapshot_ticks": after_ticks,
        },
        "thresholds": {
            "rss_kib": rss_threshold,
            "cpu_milli_percent": cpu_threshold,
        },
    }


def _status(
    pid: int,
    start_ticks: int,
    *,
    comm: str = "worker",
    state: str = "S",
    ppid: int = 1,
    uid: int = 1000,
    rss_kib: int = 2_048,
    cpu_milli_percent: int = 12_500,
) -> dict[str, object]:
    return {
        "comm": comm,
        "cpu_milli_percent": cpu_milli_percent,
        "pid": pid,
        "ppid": ppid,
        "rss_kib": rss_kib,
        "start_ticks": start_ticks,
        "state": state,
        "uid": uid,
    }


def _add_process(
    entries: list[InputFile | InputSymlink],
    side: str,
    status: dict[str, object],
    *,
    argv: list[str] | None = None,
    cgroups: list[str] | None = None,
    status_mode: int = 0o600,
    argv_mode: int = 0o600,
    cgroups_mode: int = 0o600,
) -> None:
    pid = status["pid"]
    root = f"input/process-lifecycle/{side}/{pid}"
    entries.append(
        InputFile(
            f"{root}/status.json",
            _canonical(status),
            status_mode,
            10_000 + int(pid),
        )
    )
    if argv is not None:
        entries.append(
            InputFile(
                f"{root}/cmdline.json",
                _canonical(argv),
                argv_mode,
                20_000 + int(pid),
            )
        )
    if cgroups is not None:
        entries.append(
            InputFile(
                f"{root}/cgroups.json",
                _canonical(cgroups),
                cgroups_mode,
                30_000 + int(pid),
            )
        )


def _definition(
    before: list[dict[str, object]],
    after: list[dict[str, object]],
    *,
    argv: dict[tuple[str, int], list[str]] | None = None,
    cgroups: dict[tuple[str, int], list[str]] | None = None,
    extras: tuple[InputFile | InputSymlink, ...] = (),
    fixture_id: str = "fixture.process-lifecycle-manual",
) -> FixtureDefinition:
    entries: list[InputFile | InputSymlink] = [
        InputFile(
            "input/process-lifecycle/pair.json",
            _canonical(_pair()),
            0o600,
            9_999,
        )
    ]
    argv = {} if argv is None else argv
    cgroups = {} if cgroups is None else cgroups
    for side, statuses in (("before", before), ("after", after)):
        for item in statuses:
            pid = int(item["pid"])
            _add_process(
                entries,
                side,
                item,
                argv=argv.get((side, pid), []),
                cgroups=cgroups.get((side, pid), []),
            )
    entries.extend(extras)
    for side in ("before", "after"):
        entries.append(
            InputFile(
                f"input/process-lifecycle/{side}/distractors/keep",
                b"anchor\n",
                0o400,
                40_000 if side == "before" else 40_001,
            )
        )
    return FixtureDefinition(fixture_id, tuple(entries), ())


def _write_output(handle: object, content: bytes) -> None:
    output = handle.workspace / "output"
    output.mkdir(mode=0o755)
    path = output / "transitions.jsonl"
    path.write_bytes(content)
    path.chmod(0o644)


class ProcessLifecycleTaskTests(unittest.TestCase):
    def test_grid_is_exact_unique_public_and_label_free(self) -> None:
        expected = tuple(
            (snapshot_pair, policy)
            for snapshot_pair in PROCESS_LIFECYCLE_DELTA_SNAPSHOT_PAIRS
            for policy in PROCESS_LIFECYCLE_DELTA_SELECTION_POLICIES
        )
        self.assertEqual(
            tuple(
                (
                    task.parameters.snapshot_pair,
                    task.parameters.selection_policy,
                )
                for task in TASKS
            ),
            expected,
        )
        self.assertEqual(len(TASKS), 20)
        self.assertEqual(len({task.task_id for task in TASKS}), 20)
        self.assertEqual(
            len({task.task_contract_sha256 for task in TASKS}), 20
        )
        self.assertEqual(len({task.graph_sha256 for task in TASKS}), 20)
        self.assertEqual(
            compute_process_lifecycle_delta_discrimination_sha256(TASKS),
            EXPECTED_DISCRIMINATION_SHA256,
        )
        for task in TASKS:
            self.assertEqual(
                task.family_id, PROCESS_LIFECYCLE_DELTA_FAMILY_ID
            )
            self.assertEqual(
                task.allowed_tools, PROCESS_LIFECYCLE_DELTA_ALLOWED_TOOLS
            )
            self.assertTrue(task.public)
            self.assertFalse(task.sealed)
            self.assertFalse(task.candidate_execution_authorized)
            self.assertFalse(task.model_selection_eligible)
            self.assertFalse(task.claim_authorized)
            self.assertEqual(len(task.fixtures), 5)

    def test_discrimination_is_output_only_and_20_of_20_per_profile(
        self,
    ) -> None:
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
            bundles = tuple(
                build_process_lifecycle_delta_fixture_bundle(task, profile)
                for task in TASKS
            )
            output_hashes = tuple(
                sha256(bundle.oracle.state.content).hexdigest()
                for bundle in bundles
            )
            signatures = tuple(
                lifecycle._discrimination_signature(bundle)
                for bundle in bundles
            )
            self.assertTrue(
                all(bundle.oracle.state.content for bundle in bundles)
            )
            self.assertEqual(len(set(output_hashes)), 20)
            self.assertEqual(len(set(signatures)), 20)

        state = bundles[0].oracle.state
        forged_metadata = copy.copy(state)
        object.__setattr__(
            forged_metadata,
            "before_valid_count",
            state.before_valid_count + 1,
        )
        object.__setattr__(
            forged_metadata,
            "unknown_pids",
            (*state.unknown_pids, PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID),
        )
        self.assertEqual(
            lifecycle._behavioral_outcome_sha256(state),
            lifecycle._behavioral_outcome_sha256(forged_metadata),
        )

    def test_hashed_prompt_is_self_contained_for_contract_bounds(self) -> None:
        required_fragments = (
            "no hardlinks",
            "owner-read bit 0400",
            "at most 4096 bytes",
            "no BOM or NUL",
            "9007199254740991",
            "depth 8",
            "4096 total nodes",
            "32 members per object",
            "32 items per array",
            "8388608 bytes",
            "at most 64 names per endpoint",
            "128 in the endpoint union",
            "1..4194304",
            "0..4294967295",
            "0..100000",
            "`R,S,D,Z,T,I`",
            "1..64 UTF-8 bytes",
            "Unicode Cc or Cf",
            "each 0..128 UTF-8 bytes",
            "at most 512 bytes in aggregate",
            "strict raw-UTF-8 byte order",
            "forbid NUL, CR, LF",
            "at most 1048576 bytes",
            "one-link mode-0644",
            "`threshold_crossings`",
            "exited/started/changed",
            "ends in exactly one LF",
        )
        for task in TASKS:
            normalized_prompt = " ".join(task.prompt.split())
            for fragment in required_fragments:
                with self.subTest(
                    task=task.task_id,
                    fragment=fragment,
                ):
                    self.assertIn(fragment, normalized_prompt)
            self.assertNotIn(
                "rules are those in the task contract",
                task.prompt,
            )

    def test_exact_type_authority_and_no_production_asserts(self) -> None:
        class TextSubclass(str):
            pass

        with self.assertRaises(ProcessLifecycleDeltaError):
            ProcessLifecycleDeltaParameters(
                TextSubclass("status-only"), "all-changes"
            )
        task = TASKS[0]
        with self.assertRaises(ProcessLifecycleDeltaError):
            replace(task, family_id=TextSubclass(task.family_id))
        with self.assertRaises(ProcessLifecycleDeltaError):
            replace(task, candidate_execution_authorized=True)
        with self.assertRaises(ProcessLifecycleDeltaError):
            replace(
                task,
                fixtures=(
                    OpaqueFixtureDescriptor(
                        task.fixtures[0].fixture_id,
                        task.fixtures[0].fixture_sha256,
                        "0" * 64,
                    ),
                    *task.fixtures[1:],
                ),
            )
        source = (
            ROOT
            / "src/cbds/executable_process_lifecycle_delta.py"
        ).read_text(encoding="utf-8")
        self.assertFalse(
            any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(source)))
        )
        self.assertNotIn("/proc/", source)
        self.assertNotIn("subprocess", source)

    def test_observation_and_nonclaim_boundaries_are_explicit(self) -> None:
        self.assertTrue(PROCESS_LIFECYCLE_DELTA_FINAL_OUTPUT_OBSERVED)
        self.assertTrue(PROCESS_LIFECYCLE_DELTA_INPUT_PRESERVATION_OBSERVED)
        self.assertFalse(PROCESS_LIFECYCLE_DELTA_ATOMICITY_OBSERVED)
        self.assertFalse(PROCESS_LIFECYCLE_DELTA_TOOL_HISTORY_OBSERVED)
        self.assertFalse(PROCESS_LIFECYCLE_DELTA_READ_SCOPE_OBSERVED)
        self.assertFalse(
            PROCESS_LIFECYCLE_DELTA_CANDIDATE_EXIT_STATUS_OBSERVED
        )
        self.assertFalse(PROCESS_LIFECYCLE_DELTA_TRANSIENT_STATE_OBSERVED)
        self.assertFalse(PROCESS_LIFECYCLE_DELTA_LIVE_PROC_OBSERVED)
        self.assertFalse(PROCESS_LIFECYCLE_DELTA_PROCESS_ACTIONS_OBSERVED)
        self.assertTrue(
            PROCESS_LIFECYCLE_DELTA_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE
        )
        self.assertFalse(
            PROCESS_LIFECYCLE_DELTA_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE
        )


class ProcessLifecycleSemanticTests(unittest.TestCase):
    def test_completely_empty_endpoints_derive_empty_state(self) -> None:
        definition = _definition(
            [],
            [],
            fixture_id="fixture.process-lifecycle-empty-endpoints",
        )
        for snapshot_pair in PROCESS_LIFECYCLE_DELTA_SNAPSHOT_PAIRS:
            for policy in PROCESS_LIFECYCLE_DELTA_SELECTION_POLICIES:
                parameters = ProcessLifecycleDeltaParameters(
                    snapshot_pair, policy
                )
                primary = derive_process_lifecycle_delta_state(
                    definition, parameters
                )
                reference = reference_process_lifecycle_delta_state(
                    definition, parameters
                )
                self.assertEqual(primary, reference)
                self.assertEqual(primary.before_valid_count, 0)
                self.assertEqual(primary.after_valid_count, 0)
                self.assertEqual(primary.unknown_pids, ())
                self.assertEqual(primary.events, ())
                self.assertEqual(primary.content, b"")

    def test_manual_truth_table_pid_reuse_and_threshold_boundaries(self) -> None:
        before = [
            _status(2, 100, comm="exit"),
            _status(4, 200, state="S", comm="state old"),
            _status(
                5,
                300,
                rss_kib=4_095,
                cpu_milli_percent=50_000,
                comm="cross",
            ),
            _status(7, 400, comm="old generation"),
            _status(8, 500, comm="unchanged"),
        ]
        after = [
            _status(3, 1_500, comm="start"),
            _status(4, 200, state="R", comm="state new"),
            _status(
                5,
                300,
                rss_kib=4_096,
                cpu_milli_percent=49_999,
                comm="cross",
            ),
            _status(7, 1_700, comm="new generation"),
            _status(8, 500, comm="unchanged"),
            _status(9, 1_000, comm="too old"),
        ]
        definition = _definition(before, after)
        parameters = ProcessLifecycleDeltaParameters(
            "status-only", "all-changes"
        )
        state = derive_process_lifecycle_delta_state(
            definition, parameters
        )
        self.assertEqual(
            tuple((event.pid, event.event) for event in state.events),
            (
                (2, "exited"),
                (3, "started"),
                (4, "changed"),
                (5, "changed"),
                (7, "exited"),
                (7, "started"),
            ),
        )
        self.assertIn(9, state.unknown_pids)
        changed = {event.pid: event for event in state.events if event.event == "changed"}
        self.assertEqual(changed[4].changed_fields, ("state", "comm"))
        self.assertEqual(
            changed[5].threshold_crossings.rss_kib, "upward"
        )
        self.assertEqual(
            changed[5].threshold_crossings.cpu_milli_percent,
            "downward",
        )
        self.assertEqual(
            reference_process_lifecycle_delta_state(
                definition, parameters
            ),
            state,
        )

    def test_unknown_is_not_absence_and_projection_is_mode_local(self) -> None:
        status = _status(2, 100, comm="before")
        changed = _status(2, 100, comm="after")
        original = _definition([status], [changed])
        definition = FixtureDefinition(
            "fixture.process-lifecycle-malformed-nonrequired",
            tuple(
                InputFile(
                    item.path,
                    b'["unterminated"\n',
                    item.mode,
                    item.mtime_seconds,
                )
                if type(item) is InputFile
                and item.path
                == "input/process-lifecycle/before/2/cmdline.json"
                else item
                for item in original.inputs
            ),
            (),
        )
        status_state = derive_process_lifecycle_delta_state(
            definition,
            ProcessLifecycleDeltaParameters(
                "status-only", "all-changes"
            ),
        )
        self.assertEqual(
            tuple((event.pid, event.event) for event in status_state.events),
            ((2, "changed"),),
        )
        cmdline_state = derive_process_lifecycle_delta_state(
            definition,
            ProcessLifecycleDeltaParameters(
                "status-and-cmdline", "all-changes"
            ),
        )
        self.assertEqual(cmdline_state.events, ())
        self.assertEqual(cmdline_state.unknown_pids, (2,))

    def test_missing_unreadable_symlink_and_malformed_are_unknown(self) -> None:
        entries: list[InputFile | InputSymlink] = [
            InputFile(
                "input/process-lifecycle/pair.json",
                _canonical(_pair()),
                0o600,
                1,
            )
        ]
        # Missing status, unreadable status, status symlink, PID mismatch.
        entries.append(
            InputFile(
                "input/process-lifecycle/before/2/keep",
                b"x",
                0o400,
                2,
            )
        )
        _add_process(
            entries,
            "before",
            _status(3, 100),
            argv=[],
            cgroups=[],
            status_mode=0o000,
        )
        entries.extend(
            (
                InputFile(
                    "input/process-lifecycle/before/4/target.json",
                    _canonical(_status(4, 100)),
                    0o600,
                    4,
                ),
                InputSymlink(
                    "input/process-lifecycle/before/4/status.json",
                    "target.json",
                ),
                InputFile(
                    "input/process-lifecycle/before/5/status.json",
                    _canonical(_status(6, 100)),
                    0o600,
                    5,
                ),
            )
        )
        for pid in (2, 3, 4, 5):
            _add_process(
                entries,
                "after",
                _status(pid, 1_500),
                argv=[],
                cgroups=[],
            )
        entries.extend(
            (
                InputFile(
                    "input/process-lifecycle/before/distractors/keep",
                    b"x",
                    0o400,
                    10,
                ),
                InputFile(
                    "input/process-lifecycle/after/distractors/keep",
                    b"x",
                    0o400,
                    11,
                ),
            )
        )
        definition = FixtureDefinition(
            "fixture.process-lifecycle-unknowns",
            tuple(entries),
            (),
        )
        state = derive_process_lifecycle_delta_state(
            definition,
            ProcessLifecycleDeltaParameters(
                "status-only", "all-changes"
            ),
        )
        self.assertEqual(state.events, ())
        self.assertEqual(state.unknown_pids, (2, 3, 4, 5))

    def test_all_policies_are_order_preserving_subsets(self) -> None:
        profile = PROFILE_BY_ID["spaces-unicode"]
        for snapshot_pair in PROCESS_LIFECYCLE_DELTA_SNAPSHOT_PAIRS:
            all_task = TASK_BY_CELL[(snapshot_pair, "all-changes")]
            all_bundle = build_process_lifecycle_delta_fixture_bundle(
                all_task, profile
            )
            all_rows = [
                event.to_value() for event in all_bundle.oracle.state.events
            ]
            self.assertTrue(all_rows)
            for policy in PROCESS_LIFECYCLE_DELTA_SELECTION_POLICIES[1:]:
                task = TASK_BY_CELL[(snapshot_pair, policy)]
                bundle = build_process_lifecycle_delta_fixture_bundle(
                    task, profile
                )
                rows = [
                    event.to_value() for event in bundle.oracle.state.events
                ]
                positions = [all_rows.index(row) for row in rows]
                self.assertEqual(positions, sorted(positions))
                self.assertTrue(rows)

    def test_projection_shapes_and_sidecar_semantics(self) -> None:
        profile = PROFILE_BY_ID["spaces-unicode"]
        expected_extra = {
            "status-only": set(),
            "status-and-cmdline": {"argv"},
            "status-and-cgroups": {"cgroups"},
            "complete-synthetic-proc": {"argv", "cgroups"},
        }
        base = {
            "comm",
            "cpu_milli_percent",
            "pid",
            "ppid",
            "rss_kib",
            "start_ticks",
            "state",
            "uid",
        }
        for snapshot_pair in PROCESS_LIFECYCLE_DELTA_SNAPSHOT_PAIRS:
            bundle = build_process_lifecycle_delta_fixture_bundle(
                TASK_BY_CELL[(snapshot_pair, "all-changes")],
                profile,
            )
            for event in bundle.oracle.state.events:
                for projection in (event.before, event.after):
                    if projection is not None:
                        self.assertEqual(
                            set(projection.to_value()),
                            base | expected_extra[snapshot_pair],
                        )

    def test_primary_and_reference_helpers_are_independent(self) -> None:
        task = TASK_BY_CELL[("complete-synthetic-proc", "all-changes")]
        bundle = build_process_lifecycle_delta_fixture_bundle(
            task, PROFILE_BY_ID["spaces-unicode"]
        )
        expected = bundle.oracle.state
        primary_only_helpers = (
            "_revalidate_definition",
            "_canonical_pid",
            "_discover_endpoint_pids",
            "_parse_pair_payload",
            "_parse_status_payload",
            "_parse_argv_payload",
            "_parse_cgroups_payload",
            "_load_pair_primary",
            "_classify_endpoint_primary",
            "_derive_primary_events",
            "_primary_changed_fields",
            "_primary_crossings",
            "_started_event",
            "_exited_event",
            "_changed_event",
            "_event_selected",
            "_projection_changed_fields",
            "_projection_crossings",
            "_temporally_suppressed_pids",
            "_build_state",
        )
        self.assertEqual(len(primary_only_helpers), 20)
        with ExitStack() as stack:
            for helper in primary_only_helpers:
                stack.enter_context(
                    mock.patch.object(
                        lifecycle,
                        helper,
                        side_effect=AssertionError(
                            f"primary helper called: {helper}"
                        ),
                    )
                )
            self.assertEqual(
                reference_process_lifecycle_delta_state(
                    bundle.definition, task.parameters
                ),
                expected,
            )
        with (
            mock.patch.object(
                lifecycle,
                "_load_pair_reference",
                side_effect=AssertionError("reference pair called"),
            ),
            mock.patch.object(
                lifecycle,
                "_classify_endpoint_reference",
                side_effect=AssertionError("reference classifier called"),
            ),
            mock.patch.object(
                lifecycle,
                "_derive_reference_events",
                side_effect=AssertionError("reference join called"),
            ),
            mock.patch.object(
                lifecycle,
                "_reference_changed_fields",
                side_effect=AssertionError("reference diff called"),
            ),
            mock.patch.object(
                lifecycle,
                "_reference_crossings",
                side_effect=AssertionError("reference crossing called"),
            ),
        ):
            self.assertEqual(
                derive_process_lifecycle_delta_state(
                    bundle.definition, task.parameters
                ),
                expected,
            )

    def test_deterministic_random_pairs_agree_across_all_cells(self) -> None:
        rng = random.Random(0x51A7E)
        for sample in range(10):
            before: list[dict[str, object]] = []
            after: list[dict[str, object]] = []
            argv: dict[tuple[str, int], list[str]] = {}
            cgroups: dict[tuple[str, int], list[str]] = {}
            for pid in range(2, 10):
                start = 100 + pid
                relation = rng.randrange(5)
                if relation != 0:
                    before.append(
                        _status(
                            pid,
                            start,
                            state=rng.choice(["S", "R"]),
                            rss_kib=rng.choice([4_095, 4_096, 5_000]),
                            cpu_milli_percent=rng.choice(
                                [49_999, 50_000, 60_000]
                            ),
                        )
                    )
                    argv[("before", pid)] = ["bash", str(sample), str(pid)]
                    cgroups[("before", pid)] = [f"/before/{pid}"]
                if relation != 1:
                    after_start = 1_500 if relation == 2 else start
                    after.append(
                        _status(
                            pid,
                            after_start,
                            state=rng.choice(["S", "R"]),
                            rss_kib=rng.choice([4_095, 4_096, 5_000]),
                            cpu_milli_percent=rng.choice(
                                [49_999, 50_000, 60_000]
                            ),
                        )
                    )
                    argv[("after", pid)] = ["bash", str(pid), str(sample)]
                    cgroups[("after", pid)] = [f"/after/{pid}"]
            definition = _definition(
                before,
                after,
                argv=argv,
                cgroups=cgroups,
                fixture_id=f"fixture.random-process-{sample}",
            )
            for snapshot_pair in PROCESS_LIFECYCLE_DELTA_SNAPSHOT_PAIRS:
                for policy in PROCESS_LIFECYCLE_DELTA_SELECTION_POLICIES:
                    parameters = ProcessLifecycleDeltaParameters(
                        snapshot_pair, policy
                    )
                    self.assertEqual(
                        derive_process_lifecycle_delta_state(
                            definition, parameters
                        ),
                        reference_process_lifecycle_delta_state(
                            definition, parameters
                        ),
                    )

    def test_input_order_and_noncanonical_distractors_are_metamorphic(self) -> None:
        task = TASK_BY_CELL[("complete-synthetic-proc", "all-changes")]
        bundle = build_process_lifecycle_delta_fixture_bundle(
            task, PROFILE_BY_ID["spaces-unicode"]
        )
        original = derive_process_lifecycle_delta_state(
            bundle.definition, task.parameters
        )
        reversed_definition = FixtureDefinition(
            "fixture.reversed-process-input",
            tuple(reversed(bundle.definition.inputs)),
            (),
        )
        self.assertEqual(
            derive_process_lifecycle_delta_state(
                reversed_definition, task.parameters
            ),
            original,
        )
        distractor_definition = FixtureDefinition(
            "fixture.distracted-process-input",
            (
                *bundle.definition.inputs,
                InputFile(
                    "input/process-lifecycle/before/0007/status.json",
                    b"malformed distractor\n",
                    0o400,
                    55_555,
                ),
            ),
            (),
        )
        self.assertEqual(
            derive_process_lifecycle_delta_state(
                distractor_definition, task.parameters
            ),
            original,
        )


class ProcessLifecycleInputBoundaryTests(unittest.TestCase):
    def test_authenticated_hardlinks_are_outside_family_domain(self) -> None:
        original = _definition(
            [_status(2, 100)],
            [_status(2, 100, comm="changed")],
            fixture_id="fixture.process-lifecycle-hardlink-base",
        )
        definition = FixtureDefinition(
            "fixture.process-lifecycle-hardlink-rejected",
            (
                *original.inputs,
                InputHardlink(
                    "input/process-lifecycle/zz-pair-alias.json",
                    "input/process-lifecycle/pair.json",
                ),
            ),
            (),
        )
        parameters = ProcessLifecycleDeltaParameters(
            "status-only", "all-changes"
        )
        with self.assertRaisesRegex(
            ProcessLifecycleDeltaError, "hardlinks"
        ):
            derive_process_lifecycle_delta_state(definition, parameters)
        with self.assertRaisesRegex(
            ProcessLifecycleDeltaError, "hardlinks"
        ):
            reference_process_lifecycle_delta_state(
                definition, parameters
            )

    def test_pair_boot_time_threshold_and_integer_boundaries(self) -> None:
        valid = _canonical(_pair())
        metadata = lifecycle._parse_pair_payload(valid)
        self.assertEqual(metadata.boot_id, BOOT_ID)
        attacker_integer = b"9" * 3_500
        attacker_payload = valid.replace(
            b'"snapshot_ticks":1000',
            b'"snapshot_ticks":' + attacker_integer,
            1,
        )
        self.assertLessEqual(
            len(attacker_payload),
            lifecycle.PROCESS_LIFECYCLE_DELTA_PAIR_MAXIMUM_BYTES,
        )
        with self.assertRaises(ProcessLifecycleDeltaError):
            lifecycle._parse_pair_payload(attacker_payload)
        for mutation in (
            {**_pair(), "schema_version": True},
            {
                **_pair(),
                "after": {
                    "boot_id": "ffffffff-ffff-ffff-ffff-ffffffffffff",
                    "snapshot_ticks": 2_000,
                },
            },
            _pair(before_ticks=2_000, after_ticks=2_000),
            _pair(cpu_threshold=100_001),
            _pair(rss_threshold=0),
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(ProcessLifecycleDeltaError):
                    lifecycle._parse_pair_payload(_canonical(mutation))
        maximum = _pair(
            before_ticks=PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER - 1,
            after_ticks=PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER,
            rss_threshold=PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER,
            cpu_threshold=100_000,
        )
        lifecycle._parse_pair_payload(_canonical(maximum))
        unsafe = _canonical(
            {
                **maximum,
                "after": {
                    "boot_id": BOOT_ID,
                    "snapshot_ticks": (
                        PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER + 1
                    ),
                },
            }
        )
        with self.assertRaises(ProcessLifecycleDeltaError):
            lifecycle._parse_pair_payload(unsafe)

    def test_status_pid_unicode_and_future_boundaries(self) -> None:
        lifecycle._parse_status_payload(
            _canonical(
                _status(
                    PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
                    2_000,
                    comm="\\" * 64,
                    uid=4_294_967_295,
                    rss_kib=PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER,
                    cpu_milli_percent=100_000,
                )
            ),
            expected_pid=PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
            endpoint_ticks=2_000,
        )
        mutations = (
            _status(PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID + 1, 100),
            _status(2, 100, comm="x" * 65),
            _status(2, 100, comm="bad\ncomm"),
            _status(2, 2_001),
            {**_status(2, 100), "pid": True},
            {**_status(2, 100), "cpu_milli_percent": 100_001},
        )
        for value in mutations:
            with self.subTest(value=value):
                with self.assertRaises(ProcessLifecycleDeltaError):
                    lifecycle._parse_status_payload(
                        _canonical(value),
                        expected_pid=2,
                        endpoint_ticks=2_000,
                    )

    def test_sidecar_count_item_aggregate_order_and_duplicate_boundaries(
        self,
    ) -> None:
        lifecycle._parse_argv_payload(
            _canonical(["x" * 128] * 4 + [""] * 28)
        )
        for value in (
            ["x" * 129],
            ["x" * 128] * 4 + ["y"],
            [""] * 33,
        ):
            with self.subTest(argv=value):
                with self.assertRaises(ProcessLifecycleDeltaError):
                    lifecycle._parse_argv_payload(_canonical(value))
        lifecycle._parse_cgroups_payload(
            _canonical(["/" + chr(97 + index) + "x" * 126 for index in range(4)])
        )
        for value in (
            ["/duplicate", "/duplicate"],
            ["/z", "/a"],
            ["relative"],
            ["/bad\npath"],
            ["/" + "x" * 128],
        ):
            with self.subTest(cgroups=value):
                with self.assertRaises(ProcessLifecycleDeltaError):
                    lifecycle._parse_cgroups_payload(_canonical(value))

    def test_canonical_json_duplicate_number_framing_and_size_fail_closed(
        self,
    ) -> None:
        pair = _canonical(_pair())
        for payload in (
            pair[:-1],
            pair + b"\n",
            b"\xef\xbb\xbf" + pair,
            pair.replace(b":1,", b":1.0,", 1),
            pair.replace(b":1,", b":true,", 1),
            pair.replace(
                b'"schema_version":1',
                b'"schema_version":1,"schema_version":1',
                1,
            ),
            b" " + pair,
            b"x" * 4_097,
        ):
            with self.subTest(payload=payload[:40]):
                with self.assertRaises(ProcessLifecycleDeltaError):
                    lifecycle._parse_pair_payload(payload)
        self.assertIsNone(lifecycle._canonical_pid("0"))
        self.assertIsNone(lifecycle._canonical_pid("07"))
        self.assertIsNone(lifecycle._canonical_pid("+7"))
        self.assertIsNone(lifecycle._canonical_pid("4194305"))
        self.assertEqual(
            lifecycle._canonical_pid(str(PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID)),
            PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
        )
        self.assertIsNone(lifecycle._canonical_pid("9" * 10_000))

    def test_sixty_four_pid_limit_and_union_limit(self) -> None:
        entries: list[InputFile | InputSymlink] = [
            InputFile(
                "input/process-lifecycle/pair.json",
                _canonical(_pair()),
                0o600,
                1,
            )
        ]
        for pid in range(1, 65):
            _add_process(
                entries,
                "before",
                _status(pid, 100),
                argv=[],
                cgroups=[],
            )
        entries.append(
            InputFile(
                "input/process-lifecycle/after/distractors/keep",
                b"x",
                0o400,
                2,
            )
        )
        at_limit = FixtureDefinition(
            "fixture.process-count-at-limit", tuple(entries), ()
        )
        state = derive_process_lifecycle_delta_state(
            at_limit,
            ProcessLifecycleDeltaParameters(
                "status-only", "exits-only"
            ),
        )
        self.assertEqual(len(state.events), 64)
        over = list(entries)
        _add_process(
            over,
            "before",
            _status(65, 100),
            argv=[],
            cgroups=[],
        )
        with self.assertRaises(ProcessLifecycleDeltaError):
            derive_process_lifecycle_delta_state(
                FixtureDefinition(
                    "fixture.process-count-over-limit",
                    tuple(over),
                    (),
                ),
                ProcessLifecycleDeltaParameters(
                    "status-only", "all-changes"
                ),
            )


class ProcessLifecycleOutputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.task = TASK_BY_CELL[("complete-synthetic-proc", "all-changes")]
        cls.bundle = build_process_lifecycle_delta_fixture_bundle(
            cls.task, PROFILE_BY_ID["spaces-unicode"]
        )
        cls.state = cls.bundle.oracle.state

    def test_semantic_formatting_and_empty_output_are_accepted(self) -> None:
        rows = [
            json.dumps(
                event.to_value(),
                ensure_ascii=False,
                sort_keys=False,
                separators=(", ", ": "),
            ).encode("utf-8")
            for event in self.state.events
        ]
        observed = b"\n".join(rows) + b"\n"
        self.assertEqual(
            parse_process_lifecycle_delta_output(
                observed, self.task.parameters, self.state.pair
            ),
            self.state.content,
        )
        empty_parameters = ProcessLifecycleDeltaParameters(
            "status-only", "starts-only"
        )
        self.assertEqual(
            parse_process_lifecycle_delta_output(
                b"", empty_parameters, self.state.pair
            ),
            b"",
        )

    def test_schema_identity_difference_crossing_and_order_mutations_fail(
        self,
    ) -> None:
        values = [event.to_value() for event in self.state.events]
        mutations: list[bytes] = []
        extra = copy.deepcopy(values)
        extra[0]["extra"] = 1
        mutations.append(b"".join(_canonical(row) for row in extra))
        wrong_pid = copy.deepcopy(values)
        projection = (
            wrong_pid[0]["before"]
            if wrong_pid[0]["before"] is not None
            else wrong_pid[0]["after"]
        )
        projection["pid"] = 999  # type: ignore[index]
        mutations.append(b"".join(_canonical(row) for row in wrong_pid))
        changed_index = next(
            index
            for index, row in enumerate(values)
            if row["event"] == "changed"
        )
        incomplete = copy.deepcopy(values)
        incomplete[changed_index]["changed_fields"] = []
        mutations.append(b"".join(_canonical(row) for row in incomplete))
        crossing = copy.deepcopy(values)
        crossing[changed_index]["threshold_crossings"]["rss_kib"] = "upward"  # type: ignore[index]
        mutations.append(b"".join(_canonical(row) for row in crossing))
        reversed_rows = list(reversed(values))
        mutations.append(b"".join(_canonical(row) for row in reversed_rows))
        mutations.extend(
            (
                self.state.content[:-1],
                self.state.content + b"\n",
                self.state.content.replace(b"\n", b"\r\n", 1),
                self.state.content + self.state.content.splitlines(True)[0],
                self.state.content.replace(b'"pid":2', b'"pid":true', 1),
                self.state.content.replace(b'"pid":2', b'"pid":2.0', 1),
                b'{"pid":'
                + b"9" * 10_000
                + b',"boot_id":"'
                + BOOT_ID.encode("ascii")
                + b'"}\n',
            )
        )
        for payload in mutations:
            with self.subTest(payload=payload[:80]):
                with self.assertRaises(ProcessLifecycleDeltaError):
                    parse_process_lifecycle_delta_output(
                        payload, self.task.parameters, self.state.pair
                    )

    def test_wrong_policy_projection_and_pair_are_rejected(self) -> None:
        with self.assertRaises(ProcessLifecycleDeltaError):
            parse_process_lifecycle_delta_output(
                self.state.content,
                ProcessLifecycleDeltaParameters(
                    "status-only", "all-changes"
                ),
                self.state.pair,
            )
        with self.assertRaises(ProcessLifecycleDeltaError):
            parse_process_lifecycle_delta_output(
                self.state.content,
                self.task.parameters,
                replace(
                    self.state.pair,
                    boot_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
                ),
            )


class ProcessLifecycleFixtureTests(unittest.TestCase):
    def test_all_100_bundles_reconstruct_with_independent_oracles(self) -> None:
        fixture_hashes: set[str] = set()
        count = 0
        for task in TASKS:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                bundle = build_process_lifecycle_delta_fixture_bundle(
                    task, profile
                )
                validate_process_lifecycle_delta_fixture_bundle(bundle)
                validate_process_lifecycle_delta_fixture_for_task_profile(
                    task, profile, bundle
                )
                self.assertTrue(
                    verify_process_lifecycle_delta_fixture_bundle(bundle)
                )
                self.assertTrue(
                    verify_process_lifecycle_delta_fixture_for_task_profile(
                        task, profile, bundle
                    )
                )
                primary = derive_process_lifecycle_delta_state(
                    bundle.definition, task.parameters
                )
                reference = reference_process_lifecycle_delta_state(
                    bundle.definition, task.parameters
                )
                self.assertEqual(primary, reference)
                self.assertEqual(primary, bundle.oracle.state)
                self.assertEqual(
                    parse_process_lifecycle_delta_output(
                        primary.content, task.parameters, primary.pair
                    ),
                    primary.content,
                )
                self.assertTrue(primary.events)
                fixture_hashes.add(bundle.descriptor.fixture_sha256)
                count += 1
        self.assertEqual(count, 100)
        self.assertEqual(len(fixture_hashes), 100)

    def test_symlink_profile_has_real_pid_100_and_numeric_row_order(self) -> None:
        task = TASK_BY_CELL[("status-only", "all-changes")]
        profile = PROFILE_BY_ID["symlinks-ordering"]
        bundle = build_process_lifecycle_delta_fixture_bundle(task, profile)
        before_pids = lifecycle._discover_endpoint_pids(
            bundle.definition, "before"
        )
        after_pids = lifecycle._discover_endpoint_pids(
            bundle.definition, "after"
        )
        canonical_pids = tuple(sorted(set(before_pids) | set(after_pids)))
        for pid in (2, 10, 100):
            self.assertIn(pid, canonical_pids)
        self.assertLess(
            canonical_pids.index(2),
            canonical_pids.index(10),
        )
        self.assertLess(
            canonical_pids.index(10),
            canonical_pids.index(100),
        )

        rows = tuple(
            json.loads(line)
            for line in bundle.oracle.state.content.splitlines()
        )
        row_pids = tuple(row["pid"] for row in rows)
        self.assertEqual(row_pids, tuple(sorted(row_pids)))
        self.assertEqual(row_pids[0], 2)
        self.assertEqual(row_pids[-1], 100)
        self.assertIn(10, bundle.oracle.state.unknown_pids)
        self.assertNotIn(10, row_pids)
        self.assertEqual(
            tuple(
                (event.pid, event.event)
                for event in bundle.oracle.state.events
                if event.pid == 100
            ),
            ((100, "exited"),),
        )

    def test_empty_duplicate_profile_covers_ignored_duplicates_and_equality(
        self,
    ) -> None:
        task = TASK_BY_CELL[("complete-synthetic-proc", "all-changes")]
        bundle = build_process_lifecycle_delta_fixture_bundle(
            task, PROFILE_BY_ID["empty-duplicates"]
        )
        self.assertTrue(
            any(
                item.path.endswith(
                    "empty-ignored-directory/.authenticated-marker"
                )
                for item in bundle.definition.inputs
            )
        )
        exits = {
            event.pid: event
            for event in bundle.oracle.state.events
            if event.pid in {13, 14}
        }
        self.assertEqual(set(exits), {13, 14})
        self.assertTrue(
            all(event.event == "exited" for event in exits.values())
        )
        left = exits[13].before
        right = exits[14].before
        self.assertIsNotNone(left)
        self.assertIsNotNone(right)
        left_value = left.to_value()  # type: ignore[union-attr]
        right_value = right.to_value()  # type: ignore[union-attr]
        left_value.pop("pid")
        right_value.pop("pid")
        self.assertEqual(left_value, right_value)
        equal = next(
            event
            for event in bundle.oracle.state.events
            if event.pid == 15
        )
        self.assertEqual(equal.event, "changed")
        self.assertEqual(equal.changed_fields, ("comm",))
        self.assertIsNone(equal.threshold_crossings.rss_kib)
        self.assertIsNone(
            equal.threshold_crossings.cpu_milli_percent
        )

    def test_partial_permissions_has_valid_numeric_and_equal_anchors(
        self,
    ) -> None:
        task = TASK_BY_CELL[("complete-synthetic-proc", "all-changes")]
        bundle = build_process_lifecycle_delta_fixture_bundle(
            task, PROFILE_BY_ID["partial-permissions"]
        )
        events = {event.pid: event for event in bundle.oracle.state.events}
        minimum = events[1]
        maximum = events[PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID]
        self.assertEqual(minimum.event, "changed")
        self.assertEqual(maximum.event, "changed")
        for projection in (minimum.before, minimum.after):
            self.assertIsNotNone(projection)
            self.assertEqual(projection.ppid, 0)  # type: ignore[union-attr]
            self.assertEqual(projection.uid, 0)  # type: ignore[union-attr]
            self.assertEqual(projection.rss_kib, 0)  # type: ignore[union-attr]
            self.assertEqual(  # type: ignore[union-attr]
                projection.cpu_milli_percent, 0
            )
            self.assertEqual(  # type: ignore[union-attr]
                projection.start_ticks, 1
            )
        for projection in (maximum.before, maximum.after):
            self.assertIsNotNone(projection)
            self.assertEqual(  # type: ignore[union-attr]
                projection.ppid, PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID
            )
            self.assertEqual(  # type: ignore[union-attr]
                projection.uid, 4_294_967_295
            )
            self.assertEqual(  # type: ignore[union-attr]
                projection.rss_kib,
                PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER,
            )
            self.assertEqual(  # type: ignore[union-attr]
                projection.cpu_milli_percent, 100_000
            )
        equal = events[31]
        self.assertEqual(equal.changed_fields, ("comm",))
        self.assertIsNone(equal.threshold_crossings.rss_kib)
        self.assertIsNone(
            equal.threshold_crossings.cpu_milli_percent
        )

    def test_bundle_and_owned_state_mutations_fail_closed(self) -> None:
        task = TASKS[0]
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        bundle = build_process_lifecycle_delta_fixture_bundle(task, profile)
        self.assertFalse(verify_process_lifecycle_delta_fixture_bundle(object()))
        with self.assertRaises(ProcessLifecycleDeltaError):
            replace(bundle, task_contract_sha256="0" * 64)
        with self.assertRaises(ProcessLifecycleDeltaError):
            replace(bundle, candidate_execution_authorized=True)
        with self.assertRaises(ProcessLifecycleDeltaError):
            replace(
                bundle.oracle,
                oracle_sha256="0" * 64,
            )
        with self.assertRaises(FrozenInstanceError):
            bundle.oracle.state.content = b""  # type: ignore[misc]
        hostile = copy.copy(bundle.oracle.state)
        object.__setattr__(hostile, "content", b"")
        with self.assertRaises(ProcessLifecycleDeltaError):
            hostile.__post_init__()


class ProcessLifecycleBoundsAndWorkspaceTests(unittest.TestCase):
    def test_mechanical_output_bound_fits_generic_workspace(self) -> None:
        self.assertEqual(
            PROCESS_LIFECYCLE_DELTA_PROOF_CHANGED_OUTPUT_BYTES,
            855_808,
        )
        self.assertEqual(
            PROCESS_LIFECYCLE_DELTA_PROOF_DISJOINT_OUTPUT_BYTES,
            864_704,
        )
        self.assertGreater(
            PROCESS_LIFECYCLE_DELTA_PROOF_DISJOINT_OUTPUT_BYTES,
            PROCESS_LIFECYCLE_DELTA_PROOF_CHANGED_OUTPUT_BYTES,
        )
        self.assertEqual(
            compute_process_lifecycle_delta_proved_output_bound(),
            PROCESS_LIFECYCLE_DELTA_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES,
        )
        self.assertEqual(
            PROCESS_LIFECYCLE_DELTA_OUTPUT_MAXIMUM_BYTES,
            1024 * 1024,
        )
        self.assertLessEqual(
            PROCESS_LIFECYCLE_DELTA_PROVED_MAXIMUM_TOTAL_OUTPUT_BYTES,
            MAX_TOTAL_BYTES,
        )

    def test_all_100_oracle_outputs_pass_workspace_verifier(self) -> None:
        for task in TASKS:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                bundle = build_process_lifecycle_delta_fixture_bundle(
                    task, profile
                )
                with tempfile.TemporaryDirectory() as temporary:
                    handle = materialize_process_lifecycle_delta_fixture(
                        task, profile, bundle, temporary
                    )
                    try:
                        _write_output(handle, bundle.oracle.state.content)
                        self.assertTrue(
                            verify_process_lifecycle_delta_workspace(
                                task, profile, bundle, handle
                            )
                        )
                    finally:
                        handle.close()

    def test_workspace_rejects_extra_mode_semantic_and_input_mutations(
        self,
    ) -> None:
        task = TASKS[0]
        profile = PROFILE_BY_ID["spaces-unicode"]
        bundle = build_process_lifecycle_delta_fixture_bundle(task, profile)

        def run_mutation(callback) -> None:
            with tempfile.TemporaryDirectory() as temporary:
                handle = materialize_process_lifecycle_delta_fixture(
                    task, profile, bundle, temporary
                )
                try:
                    _write_output(handle, bundle.oracle.state.content)
                    callback(handle)
                    self.assertFalse(
                        verify_process_lifecycle_delta_workspace(
                            task, profile, bundle, handle
                        )
                    )
                finally:
                    handle.close()

        run_mutation(
            lambda handle: (handle.workspace / "output" / "extra").write_bytes(
                b"x"
            )
        )
        run_mutation(
            lambda handle: (
                handle.workspace / PROCESS_LIFECYCLE_DELTA_OUTPUT
            ).chmod(0o600)
        )
        run_mutation(
            lambda handle: (
                handle.workspace / PROCESS_LIFECYCLE_DELTA_OUTPUT
            ).write_bytes(b"{}\n")
        )

        def mutate_input(handle) -> None:
            path = (
                handle.workspace
                / "input/process-lifecycle/pair.json"
            )
            path.chmod(0o600)
            path.write_bytes(path.read_bytes() + b"x")

        run_mutation(mutate_input)

    def test_workspace_rejects_symlink_and_hardlink_output(self) -> None:
        task = TASKS[0]
        profile = PROFILE_BY_ID["spaces-unicode"]
        bundle = build_process_lifecycle_delta_fixture_bundle(task, profile)
        with tempfile.TemporaryDirectory() as temporary:
            handle = materialize_process_lifecycle_delta_fixture(
                task, profile, bundle, temporary
            )
            try:
                output = handle.workspace / "output"
                output.mkdir(mode=0o755)
                target = handle.workspace / "target"
                target.write_bytes(bundle.oracle.state.content)
                os.symlink("../target", output / "transitions.jsonl")
                self.assertFalse(
                    verify_process_lifecycle_delta_workspace(
                        task, profile, bundle, handle
                    )
                )
            finally:
                handle.close()
        with tempfile.TemporaryDirectory() as temporary:
            handle = materialize_process_lifecycle_delta_fixture(
                task, profile, bundle, temporary
            )
            try:
                _write_output(handle, bundle.oracle.state.content)
                os.link(
                    handle.workspace / PROCESS_LIFECYCLE_DELTA_OUTPUT,
                    handle.workspace / "linked-copy",
                )
                self.assertFalse(
                    verify_process_lifecycle_delta_workspace(
                        task, profile, bundle, handle
                    )
                )
            finally:
                handle.close()


if __name__ == "__main__":
    unittest.main()
