from __future__ import annotations

import ast
from dataclasses import replace
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_bounded_retry_state_machine as retry  # noqa: E402
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_workspace import (  # noqa: E402
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
)


def _profile(profile_id: str):
    matches = tuple(
        profile
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        if profile.profile_id == profile_id
    )
    if len(matches) != 1:
        raise AssertionError(f"expected one profile named {profile_id!r}")
    return matches[0]


def _input(definition: FixtureDefinition, path: str) -> InputFile:
    matches = tuple(item for item in definition.inputs if item.path == path)
    if len(matches) != 1 or type(matches[0]) is not InputFile:
        raise AssertionError(f"expected one regular input named {path!r}")
    return matches[0]


def _replace_input(
    definition: FixtureDefinition,
    path: str,
    *,
    content: bytes | None = None,
    mode: int | None = None,
) -> FixtureDefinition:
    changed = False
    entries = []
    for item in definition.inputs:
        if item.path == path:
            if type(item) is not InputFile:
                raise AssertionError("test mutation expected a regular input")
            item = replace(
                item,
                content=item.content if content is None else content,
                mode=item.mode if mode is None else mode,
            )
            changed = True
        entries.append(item)
    if not changed:
        raise AssertionError(f"test mutation did not find {path!r}")
    return replace(definition, inputs=tuple(entries))


def _event(
    state: str,
    visit: int,
    attempt: int,
    outcome: str,
    directive: str = "-",
    detail: str = "test event",
) -> bytes:
    return (
        f"{state}\t{visit}\t{attempt}\t{outcome}\t{directive}\t{detail}\n"
    ).encode("utf-8")


def _oracle_output(bundle, path: str) -> bytes:
    matches = tuple(output for output in bundle.oracle.outputs if output.path == path)
    if len(matches) != 1:
        raise AssertionError(f"expected one oracle output named {path!r}")
    return matches[0].content


def _attempt_rows(payload: bytes) -> tuple[tuple[str, ...], ...]:
    if not payload:
        return ()
    if not payload.endswith(b"\n"):
        raise AssertionError("attempt report is not LF terminated")
    rows = []
    for raw in payload.splitlines():
        fields = raw.decode("utf-8", errors="strict").split("\t")
        if len(fields) != 9 or fields[0] != "attempt":
            raise AssertionError("attempt report row has the wrong closed schema")
        rows.append(tuple(fields))
    return tuple(rows)


def _terminal_row(payload: bytes) -> tuple[str, ...]:
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        raise AssertionError("terminal report must be exactly one LF-terminated row")
    fields = payload[:-1].decode("utf-8", errors="strict").split("\t")
    if len(fields) != 8 or fields[0] != "terminal":
        raise AssertionError("terminal report has the wrong closed schema")
    return tuple(fields)


def _write_expected(workspace: Path, bundle) -> None:
    output_directory = workspace / "output"
    output_directory.mkdir(mode=0o755)
    os.chmod(output_directory, 0o755)
    for output in bundle.oracle.outputs:
        target = workspace / output.path
        target.write_bytes(output.content)
        os.chmod(target, output.mode)


class _StringSubclass(str):
    pass


class _BytesSubclass(bytes):
    pass


class BoundedRetryStateMachineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = retry.build_bounded_retry_state_machine_tasks()
        cls.by_pair = {
            (task.task_id, profile.profile_id): (
                retry.build_bounded_retry_state_machine_fixture_bundle(
                    task, profile
                )
            )
            for task in cls.tasks
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        }

    def task(self, model: str, policy: str):
        matches = tuple(
            task
            for task in self.tasks
            if task.parameters.transition_model == model
            and task.parameters.retry_policy == policy
        )
        self.assertEqual(len(matches), 1)
        return matches[0]

    def bundle(self, model: str, policy: str, profile_id: str):
        task = self.task(model, policy)
        return self.by_pair[(task.task_id, profile_id)]

    def test_exact_four_by_five_grid_identity_and_authority(self) -> None:
        self.assertEqual(
            retry.BOUNDED_RETRY_STATE_MACHINE_TRANSITION_MODELS,
            ("linear", "branching", "cyclic-bounded", "compensating"),
        )
        self.assertEqual(
            retry.BOUNDED_RETRY_STATE_MACHINE_RETRY_POLICIES,
            (
                "never",
                "fixed-two",
                "fixed-four",
                "until-terminal",
                "retry-transient-only",
            ),
        )
        self.assertEqual(
            retry.BOUNDED_RETRY_STATE_MACHINE_ALLOWED_TOOLS,
            ("awk", "mkdir", "sort"),
        )
        self.assertEqual(retry.BOUNDED_RETRY_STATE_MACHINE_GENERATOR_VERSION, "1.0.0")
        self.assertEqual(len(self.tasks), 20)
        self.assertEqual(
            tuple(
                (
                    task.parameters.transition_model,
                    task.parameters.retry_policy,
                )
                for task in self.tasks
            ),
            tuple(
                (model, policy)
                for model in retry.BOUNDED_RETRY_STATE_MACHINE_TRANSITION_MODELS
                for policy in retry.BOUNDED_RETRY_STATE_MACHINE_RETRY_POLICIES
            ),
        )
        self.assertEqual(len({task.task_id for task in self.tasks}), 20)
        self.assertEqual(len({task.task_contract_sha256 for task in self.tasks}), 20)
        self.assertEqual(len({task.graph_sha256 for task in self.tasks}), 20)
        for task in self.tasks:
            self.assertEqual(task.family_id, "bounded-retry-state-machine")
            self.assertEqual(task.filesystem_identity, "workflow-event-ledger")
            self.assertEqual(
                task.output_identity, "terminal-state-and-attempt-report"
            )
            self.assertEqual(len(task.fixtures), 5)
            self.assertIs(task.public, True)
            self.assertIs(task.sealed, False)
            self.assertIs(task.candidate_execution_authorized, False)
            self.assertIs(task.model_selection_eligible, False)
            self.assertIs(task.claim_authorized, False)
            record = task.to_public_record()
            self.assertIs(record["candidate_execution_authorized"], False)
            self.assertIs(record["model_selection_eligible"], False)
            self.assertIs(record["claim_authorized"], False)
            for required_contract_text in (
                "RESOLUTION is `succeeded`",
                "`event-ledger-exhausted`",
                "A compensated terminal cites",
                "number of rows in attempts.tsv",
                "at most 32768 bytes",
            ):
                self.assertIn(required_contract_text, task.prompt)

    def test_all_one_hundred_bundles_are_deterministic_and_authenticated(self) -> None:
        self.assertEqual(len(self.by_pair), 100)
        fixture_ids = set()
        fixture_hashes = set()
        for task in self.tasks:
            for profile_index, profile in enumerate(
                PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
            ):
                bundle = self.by_pair[(task.task_id, profile.profile_id)]
                rebuilt = retry.build_bounded_retry_state_machine_fixture_bundle(
                    task, profile
                )
                with self.subTest(
                    model=task.parameters.transition_model,
                    policy=task.parameters.retry_policy,
                    profile=profile.profile_id,
                ):
                    self.assertEqual(bundle, rebuilt)
                    self.assertTrue(
                        retry.verify_bounded_retry_state_machine_fixture_bundle(
                            bundle
                        )
                    )
                    self.assertTrue(
                        retry.verify_bounded_retry_state_machine_fixture_for_task_profile(
                            task, profile, bundle
                        )
                    )
                    self.assertEqual(bundle.descriptor, task.fixtures[profile_index])
                    self.assertEqual(len(bundle.oracle.outputs), 2)
                    self.assertEqual(
                        {output.path for output in bundle.oracle.outputs},
                        {
                            retry.BOUNDED_RETRY_STATE_MACHINE_ATTEMPTS_OUTPUT,
                            retry.BOUNDED_RETRY_STATE_MACHINE_TERMINAL_OUTPUT,
                        },
                    )
                    self.assertIs(bundle.candidate_execution_authorized, False)
                    self.assertIs(bundle.model_selection_eligible, False)
                    self.assertIs(bundle.claim_authorized, False)
                    fixture_ids.add(bundle.descriptor.fixture_id)
                    fixture_hashes.add(bundle.descriptor.fixture_sha256)
        self.assertEqual(len(fixture_ids), 100)
        self.assertEqual(len(fixture_hashes), 100)

    def test_dual_oracles_agree_for_all_bundles_and_reports_crosscheck(self) -> None:
        for task in self.tasks:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                bundle = self.by_pair[(task.task_id, profile.profile_id)]
                primary = retry.derive_bounded_retry_state_machine_output(
                    bundle.definition, task.parameters
                )
                reference = retry.reference_bounded_retry_state_machine_output(
                    bundle.definition, task.parameters
                )
                with self.subTest(
                    model=task.parameters.transition_model,
                    policy=task.parameters.retry_policy,
                    profile=profile.profile_id,
                ):
                    self.assertEqual(primary, reference)
                    self.assertTrue(
                        retry.verify_bounded_retry_state_machine_output(
                            bundle.definition, task.parameters, primary
                        )
                    )
                    self.assertEqual(
                        primary.attempts,
                        _oracle_output(
                            bundle,
                            retry.BOUNDED_RETRY_STATE_MACHINE_ATTEMPTS_OUTPUT,
                        ),
                    )
                    self.assertEqual(
                        primary.terminal,
                        _oracle_output(
                            bundle,
                            retry.BOUNDED_RETRY_STATE_MACHINE_TERMINAL_OUTPUT,
                        ),
                    )
                    attempts = _attempt_rows(primary.attempts)
                    terminal = _terminal_row(primary.terminal)
                    self.assertEqual(
                        tuple(int(row[1]) for row in attempts),
                        tuple(range(1, len(attempts) + 1)),
                    )
                    self.assertEqual(int(terminal[3]), len(attempts))
                    self.assertTrue(
                        all(row[8] in {"retry", "succeeded", "failed"} for row in attempts)
                    )

    def _linear_definition(self, policy: str, prepare: bytes) -> tuple[object, FixtureDefinition]:
        task = self.task("linear", policy)
        base = self.bundle("linear", policy, "spaces-unicode")
        tail = (
            _event("execute", 1, 1, "success", "next", "execute succeeds")
            + _event("publish", 1, 1, "success", "next", "publish succeeds")
        )
        definition = _replace_input(
            base.definition,
            retry.BOUNDED_RETRY_STATE_MACHINE_EVENTS,
            content=prepare + tail,
        )
        return task, definition

    def test_hand_checked_retry_policy_witness_table(self) -> None:
        traces = {
            "success": (_event("prepare", 1, 1, "success", "next"),),
            "transient-success": (
                _event("prepare", 1, 1, "transient-failure"),
                _event("prepare", 1, 2, "success", "next"),
            ),
            "two-transient-success": (
                _event("prepare", 1, 1, "transient-failure"),
                _event("prepare", 1, 2, "transient-failure"),
                _event("prepare", 1, 3, "success", "next"),
            ),
            "four-transient-success": tuple(
                _event("prepare", 1, attempt, "transient-failure")
                for attempt in range(1, 5)
            )
            + (_event("prepare", 1, 5, "success", "next"),),
            "ordinary-success": (
                _event("prepare", 1, 1, "ordinary-failure"),
                _event("prepare", 1, 2, "success", "next"),
            ),
            "terminal-failure": (
                _event("prepare", 1, 1, "terminal-failure"),
            ),
        }
        expected = {
            "success": {
                policy: ("complete", "workflow-complete", 3)
                for policy in retry.BOUNDED_RETRY_STATE_MACHINE_RETRY_POLICIES
            },
            "transient-success": {
                "never": ("failed", "retry-disabled", 1),
                "fixed-two": ("complete", "workflow-complete", 4),
                "fixed-four": ("complete", "workflow-complete", 4),
                "until-terminal": ("complete", "workflow-complete", 4),
                "retry-transient-only": ("complete", "workflow-complete", 4),
            },
            "two-transient-success": {
                "never": ("failed", "retry-disabled", 1),
                "fixed-two": ("failed", "retry-budget-exhausted", 2),
                "fixed-four": ("complete", "workflow-complete", 5),
                "until-terminal": ("complete", "workflow-complete", 5),
                "retry-transient-only": ("complete", "workflow-complete", 5),
            },
            "four-transient-success": {
                "never": ("failed", "retry-disabled", 1),
                "fixed-two": ("failed", "retry-budget-exhausted", 2),
                "fixed-four": ("failed", "retry-budget-exhausted", 4),
                "until-terminal": ("complete", "workflow-complete", 7),
                "retry-transient-only": ("complete", "workflow-complete", 7),
            },
            "ordinary-success": {
                "never": ("failed", "retry-disabled", 1),
                "fixed-two": ("complete", "workflow-complete", 4),
                "fixed-four": ("complete", "workflow-complete", 4),
                "until-terminal": ("complete", "workflow-complete", 4),
                "retry-transient-only": ("failed", "nontransient-failure", 1),
            },
            "terminal-failure": {
                policy: ("failed", "terminal-failure", 1)
                for policy in retry.BOUNDED_RETRY_STATE_MACHINE_RETRY_POLICIES
            },
        }
        for trace_name, rows in traces.items():
            for policy in retry.BOUNDED_RETRY_STATE_MACHINE_RETRY_POLICIES:
                task, definition = self._linear_definition(policy, b"".join(rows))
                primary = retry.derive_bounded_retry_state_machine_output(
                    definition, task.parameters
                )
                reference = retry.reference_bounded_retry_state_machine_output(
                    definition, task.parameters
                )
                terminal = _terminal_row(primary.terminal)
                with self.subTest(trace=trace_name, policy=policy):
                    self.assertEqual(primary, reference)
                    self.assertEqual(
                        (terminal[1], terminal[2], int(terminal[3])),
                        expected[trace_name][policy],
                    )
                    attempts = _attempt_rows(primary.attempts)
                    self.assertEqual(len(attempts), int(terminal[3]))
                    if terminal[1] == "complete":
                        self.assertEqual(attempts[-1][2], "publish")
                        self.assertEqual(attempts[-1][8], "succeeded")
                    else:
                        self.assertEqual(attempts[-1][2], "prepare")
                        self.assertEqual(attempts[-1][8], "failed")

    def test_empty_and_missing_event_terminals_are_distinct(self) -> None:
        for policy in retry.BOUNDED_RETRY_STATE_MACHINE_RETRY_POLICIES:
            task, definition = self._linear_definition(policy, b"")
            empty = _replace_input(
                definition,
                retry.BOUNDED_RETRY_STATE_MACHINE_EVENTS,
                content=b"",
            )
            output = retry.derive_bounded_retry_state_machine_output(
                empty, task.parameters
            )
            self.assertEqual(output.attempts, b"")
            self.assertEqual(
                output.terminal,
                b"terminal\tempty\tno-events\t0\t-\t0\t0\tempty\n",
            )

            missing_after_transient = _replace_input(
                definition,
                retry.BOUNDED_RETRY_STATE_MACHINE_EVENTS,
                content=_event("prepare", 1, 1, "transient-failure"),
            )
            missing = retry.derive_bounded_retry_state_machine_output(
                missing_after_transient, task.parameters
            )
            terminal = _terminal_row(missing.terminal)
            if policy == "never":
                self.assertEqual(terminal[1:4], ("failed", "retry-disabled", "1"))
            else:
                self.assertEqual(
                    terminal[1:4],
                    ("incomplete", "event-ledger-exhausted", "1"),
                )
                self.assertEqual(terminal[4:8], ("prepare", "1", "2", "missing"))

    def test_policy_and_transition_model_fingerprints_are_pairwise_distinct(self) -> None:
        profiles = tuple(
            profile.profile_id for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        )
        for model in retry.BOUNDED_RETRY_STATE_MACHINE_TRANSITION_MODELS:
            fingerprints = {}
            for policy in retry.BOUNDED_RETRY_STATE_MACHINE_RETRY_POLICIES:
                fingerprints[policy] = tuple(
                    (
                        _oracle_output(
                            self.bundle(model, policy, profile_id),
                            retry.BOUNDED_RETRY_STATE_MACHINE_ATTEMPTS_OUTPUT,
                        ),
                        _oracle_output(
                            self.bundle(model, policy, profile_id),
                            retry.BOUNDED_RETRY_STATE_MACHINE_TERMINAL_OUTPUT,
                        ),
                    )
                    for profile_id in profiles
                )
            self.assertEqual(len(set(fingerprints.values())), 5, model)
        for policy in retry.BOUNDED_RETRY_STATE_MACHINE_RETRY_POLICIES:
            fingerprints = {}
            for model in retry.BOUNDED_RETRY_STATE_MACHINE_TRANSITION_MODELS:
                fingerprints[model] = tuple(
                    (
                        _oracle_output(
                            self.bundle(model, policy, profile_id),
                            retry.BOUNDED_RETRY_STATE_MACHINE_ATTEMPTS_OUTPUT,
                        ),
                        _oracle_output(
                            self.bundle(model, policy, profile_id),
                            retry.BOUNDED_RETRY_STATE_MACHINE_TERMINAL_OUTPUT,
                        ),
                    )
                    for profile_id in profiles
                )
            self.assertEqual(len(set(fingerprints.values())), 4, policy)

    def test_branch_selection_cycle_visits_and_retry_attempts_are_observable(self) -> None:
        fast = self.bundle("branching", "fixed-four", "spaces-unicode")
        fast_rows = _attempt_rows(
            _oracle_output(fast, retry.BOUNDED_RETRY_STATE_MACHINE_ATTEMPTS_OUTPUT)
        )
        self.assertIn("fast", {row[2] for row in fast_rows})
        self.assertNotIn("safe", {row[2] for row in fast_rows})

        safe = self.bundle("branching", "fixed-two", "leading-dashes-globs")
        safe_rows = _attempt_rows(
            _oracle_output(safe, retry.BOUNDED_RETRY_STATE_MACHINE_ATTEMPTS_OUTPUT)
        )
        self.assertIn("safe", {row[2] for row in safe_rows})
        self.assertNotIn("fast", {row[2] for row in safe_rows})

        cyclic = self.bundle(
            "cyclic-bounded", "until-terminal", "symlinks-ordering"
        )
        cyclic_rows = _attempt_rows(
            _oracle_output(cyclic, retry.BOUNDED_RETRY_STATE_MACHINE_ATTEMPTS_OUTPUT)
        )
        self.assertEqual(
            sorted({int(row[3]) for row in cyclic_rows if row[2] == "work"}),
            [1, 2, 3],
        )
        for state in ("check", "work"):
            for visit in (1, 2, 3):
                attempts = [
                    int(row[4])
                    for row in cyclic_rows
                    if row[2] == state and int(row[3]) == visit
                ]
                self.assertEqual(attempts, [1, 2, 3, 4, 5, 6])
        cyclic_terminal = _terminal_row(
            _oracle_output(cyclic, retry.BOUNDED_RETRY_STATE_MACHINE_TERMINAL_OUTPUT)
        )
        self.assertEqual(cyclic_terminal[1:3], ("complete", "workflow-complete"))

        bounded = self.bundle(
            "cyclic-bounded", "fixed-two", "leading-dashes-globs"
        )
        bounded_terminal = _terminal_row(
            _oracle_output(bounded, retry.BOUNDED_RETRY_STATE_MACHINE_TERMINAL_OUTPUT)
        )
        self.assertEqual(
            bounded_terminal[1:3],
            ("cycle-limit", "cycle-bound-exceeded"),
        )

    def test_compensation_success_failure_and_missing_event_semantics(self) -> None:
        compensated = self.bundle(
            "compensating", "fixed-four", "partial-permissions"
        )
        rows = _attempt_rows(
            _oracle_output(
                compensated, retry.BOUNDED_RETRY_STATE_MACHINE_ATTEMPTS_OUTPUT
            )
        )
        terminal = _terminal_row(
            _oracle_output(
                compensated, retry.BOUNDED_RETRY_STATE_MACHINE_TERMINAL_OUTPUT
            )
        )
        self.assertEqual([row[2] for row in rows], ["prepare", "apply", "compensate"])
        self.assertEqual(terminal[1:3], ("compensated", "compensation-complete"))
        self.assertEqual(terminal[4], "apply")
        self.assertEqual(terminal[7], "terminal-failure")

        task = self.task("compensating", "fixed-four")
        base = self.bundle("compensating", "fixed-four", "spaces-unicode")
        failure_events = (
            _event("prepare", 1, 1, "success", "next")
            + _event("apply", 1, 1, "terminal-failure")
            + _event("compensate", 1, 1, "terminal-failure")
        )
        failed_definition = _replace_input(
            base.definition,
            retry.BOUNDED_RETRY_STATE_MACHINE_EVENTS,
            content=failure_events,
        )
        failed = retry.derive_bounded_retry_state_machine_output(
            failed_definition, task.parameters
        )
        self.assertEqual(
            _terminal_row(failed.terminal)[1:3],
            ("compensation-failed", "compensation-failed"),
        )
        self.assertEqual(
            [row[2] for row in _attempt_rows(failed.attempts)],
            ["prepare", "apply", "compensate"],
        )

        missing_apply = _replace_input(
            base.definition,
            retry.BOUNDED_RETRY_STATE_MACHINE_EVENTS,
            content=(
                _event("prepare", 1, 1, "success", "next")
                + _event("compensate", 1, 1, "success", "next")
            ),
        )
        missing = retry.derive_bounded_retry_state_machine_output(
            missing_apply, task.parameters
        )
        self.assertEqual(
            _terminal_row(missing.terminal)[1:3],
            ("incomplete", "event-ledger-exhausted"),
        )

        missing_compensation = _replace_input(
            base.definition,
            retry.BOUNDED_RETRY_STATE_MACHINE_EVENTS,
            content=(
                _event("prepare", 1, 1, "success", "next")
                + _event("apply", 1, 1, "terminal-failure")
            ),
        )
        missing_primary = retry.derive_bounded_retry_state_machine_output(
            missing_compensation, task.parameters
        )
        missing_reference = retry.reference_bounded_retry_state_machine_output(
            missing_compensation, task.parameters
        )
        self.assertEqual(missing_primary, missing_reference)
        self.assertEqual(
            _terminal_row(missing_primary.terminal),
            (
                "terminal",
                "incomplete",
                "event-ledger-exhausted",
                "2",
                "compensate",
                "1",
                "1",
                "missing",
            ),
        )

    def test_each_state_visit_receives_a_fresh_retry_budget(self) -> None:
        bundle = self.bundle("linear", "fixed-four", "spaces-unicode")
        rows = _attempt_rows(
            _oracle_output(bundle, retry.BOUNDED_RETRY_STATE_MACHINE_ATTEMPTS_OUTPUT)
        )
        self.assertEqual(len(rows), 9)
        for state in ("prepare", "execute", "publish"):
            state_rows = [row for row in rows if row[2] == state]
            self.assertEqual([int(row[4]) for row in state_rows], [1, 2, 3])
            self.assertEqual([row[8] for row in state_rows], ["retry", "retry", "succeeded"])

    def test_identical_duplicates_coalesce_and_physical_order_is_nonsemantic(self) -> None:
        task, definition = self._linear_definition(
            "fixed-four",
            _event("prepare", 1, 1, "transient-failure")
            + _event("prepare", 1, 2, "success", "next"),
        )
        content = _input(
            definition, retry.BOUNDED_RETRY_STATE_MACHINE_EVENTS
        ).content
        rows = content.splitlines(keepends=True)
        reordered = _replace_input(
            definition,
            retry.BOUNDED_RETRY_STATE_MACHINE_EVENTS,
            content=b"".join(reversed(rows)),
        )
        duplicated = _replace_input(
            definition,
            retry.BOUNDED_RETRY_STATE_MACHINE_EVENTS,
            content=content + rows[0] + rows[0],
        )
        expected = retry.derive_bounded_retry_state_machine_output(
            definition, task.parameters
        )
        self.assertEqual(
            retry.derive_bounded_retry_state_machine_output(
                reordered, task.parameters
            ),
            expected,
        )
        self.assertEqual(
            retry.reference_bounded_retry_state_machine_output(
                duplicated, task.parameters
            ),
            expected,
        )

    def test_strict_event_parser_rejects_hostile_rows_and_resource_overflow(self) -> None:
        task = self.task("linear", "fixed-four")
        base = self.bundle("linear", "fixed-four", "spaces-unicode")
        valid = _event("prepare", 1, 1, "success", "next")
        invalid = (
            valid[:-1],
            b"\n",
            valid + b"\n",
            b"prepare\t1\t1\tsuccess\tnext\n",
            b"prepare\t1\t1\tsuccess\tnext\tdetail\textra\n",
            b"unknown\t1\t1\tsuccess\tnext\tdetail\n",
            b"prepare\t0\t1\tsuccess\tnext\tdetail\n",
            b"prepare\t01\t1\tsuccess\tnext\tdetail\n",
            b"prepare\t+1\t1\tsuccess\tnext\tdetail\n",
            b"prepare\t2\t1\tsuccess\tnext\tdetail\n",
            b"prepare\t1\t0\tsuccess\tnext\tdetail\n",
            b"prepare\t1\t01\tsuccess\tnext\tdetail\n",
            b"prepare\t1\t+1\tsuccess\tnext\tdetail\n",
            b"prepare\t1\t7\tsuccess\tnext\tdetail\n",
            b"prepare\t1\t1\tunknown\t-\tdetail\n",
            b"prepare\t1\t1\tsuccess\t-\tdetail\n",
            b"prepare\t1\t1\tordinary-failure\tnext\tdetail\n",
            b"prepare\t1\t1\tsuccess\tnext\t\n",
            b"prepare\t1\t1\tsuccess\tnext\tbad\0detail\n",
            b"prepare\t1\t1\tsuccess\tnext\tbad\xffdetail\n",
            b"prepar\xff\t1\t1\tsuccess\tnext\tdetail\n",
            valid
            + b"prepare\t1\t1\tsuccess\tnext\tconflicting detail\n",
            valid * 257,
            b"prepare\t1\t1\tsuccess\tnext\t"
            + b"x" * (retry.BOUNDED_RETRY_STATE_MACHINE_EVENT_LEDGER_MAXIMUM_BYTES + 1)
            + b"\n",
        )
        for payload in invalid:
            definition = _replace_input(
                base.definition,
                retry.BOUNDED_RETRY_STATE_MACHINE_EVENTS,
                content=payload,
            )
            with self.subTest(payload=payload[:80]):
                with self.assertRaises(retry.BoundedRetryStateMachineError):
                    retry.derive_bounded_retry_state_machine_output(
                        definition, task.parameters
                    )
                with self.assertRaises(retry.BoundedRetryStateMachineError):
                    retry.reference_bounded_retry_state_machine_output(
                        definition, task.parameters
                    )

        prefix = b"prepare\t1\t1\tsuccess\tnext\t"
        maximum_valid = prefix + b"x" * (
            retry.BOUNDED_RETRY_STATE_MACHINE_EVENT_LEDGER_MAXIMUM_BYTES
            - len(prefix)
            - 1
        ) + b"\n"
        bounded_definition = _replace_input(
            base.definition,
            retry.BOUNDED_RETRY_STATE_MACHINE_EVENTS,
            content=maximum_valid,
        )
        primary = retry.derive_bounded_retry_state_machine_output(
            bounded_definition, task.parameters
        )
        reference = retry.reference_bounded_retry_state_machine_output(
            bounded_definition, task.parameters
        )
        self.assertEqual(primary, reference)
        self.assertLessEqual(
            len(primary.attempts),
            retry.BOUNDED_RETRY_STATE_MACHINE_OUTPUT_MAXIMUM_BYTES,
        )

    def test_model_specific_success_directives_are_closed(self) -> None:
        cases = (
            ("branching", "choose", "next"),
            ("branching", "fast", "safe"),
            ("cyclic-bounded", "check", "repeat"),
            ("cyclic-bounded", "work", "next"),
            ("compensating", "prepare", "fast"),
        )
        for model, state, directive in cases:
            task = self.task(model, "fixed-four")
            base = self.bundle(model, "fixed-four", "spaces-unicode")
            definition = _replace_input(
                base.definition,
                retry.BOUNDED_RETRY_STATE_MACHINE_EVENTS,
                content=_event(state, 1, 1, "success", directive),
            )
            with self.subTest(model=model, state=state, directive=directive):
                self.assertFalse(
                    retry.verify_bounded_retry_state_machine_output(
                        definition,
                        task.parameters,
                        retry.BoundedRetryStateMachineOutput(
                            b"", b"terminal\tempty\tno-events\t0\t-\t0\t0\tempty\n"
                        ),
                    )
                )
                with self.assertRaises(retry.BoundedRetryStateMachineError):
                    retry.derive_bounded_retry_state_machine_output(
                        definition, task.parameters
                    )

    def test_profiles_make_declared_hostile_cases_and_honest_limits_explicit(self) -> None:
        self.assertIs(
            retry.BOUNDED_RETRY_STATE_MACHINE_SYMLINK_DISTRACTORS_COVERED,
            True,
        )
        false_boundaries = (
            retry.BOUNDED_RETRY_STATE_MACHINE_DIRECTORY_PERMISSION_ERRORS_COVERED,
            retry.BOUNDED_RETRY_STATE_MACHINE_EFFECTIVE_ACCESS_FAILURES_COVERED,
            retry.BOUNDED_RETRY_STATE_MACHINE_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
            retry.BOUNDED_RETRY_STATE_MACHINE_RETRY_HISTORY_OBSERVED,
            retry.BOUNDED_RETRY_STATE_MACHINE_TRANSITION_HISTORY_OBSERVED,
            retry.BOUNDED_RETRY_STATE_MACHINE_WAIT_HISTORY_OBSERVED,
            retry.BOUNDED_RETRY_STATE_MACHINE_TOOL_HISTORY_OBSERVED,
            retry.BOUNDED_RETRY_STATE_MACHINE_ATOMIC_PUBLICATION_HISTORY_OBSERVED,
            retry.BOUNDED_RETRY_STATE_MACHINE_TRANSIENT_INPUT_PRESERVATION_OBSERVED,
            retry.BOUNDED_RETRY_STATE_MACHINE_CANDIDATE_EXIT_STATUS_OBSERVED,
        )
        self.assertTrue(all(value is False for value in false_boundaries))
        self.assertIs(
            retry.BOUNDED_RETRY_STATE_MACHINE_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE,
            True,
        )

        spaces = self.bundle("linear", "fixed-four", "spaces-unicode")
        spaces_bytes = _input(
            spaces.definition, retry.BOUNDED_RETRY_STATE_MACHINE_EVENTS
        ).content
        self.assertIn("café 雪".encode(), spaces_bytes)
        self.assertTrue(
            any(
                type(item) is InputFile and " " in item.path
                for item in spaces.definition.inputs
            )
        )

        leading = self.bundle("linear", "fixed-two", "leading-dashes-globs")
        self.assertTrue(
            any(
                type(item) is InputFile
                and Path(item.path).name.startswith("-")
                and "*" in item.path
                and "?" in item.path
                for item in leading.definition.inputs
            )
        )

        empty = self.bundle("linear", "fixed-four", "empty-duplicates")
        self.assertEqual(
            _input(empty.definition, retry.BOUNDED_RETRY_STATE_MACHINE_EVENTS).content,
            b"",
        )
        duplicate = self.bundle("branching", "fixed-four", "empty-duplicates")
        duplicate_rows = _input(
            duplicate.definition, retry.BOUNDED_RETRY_STATE_MACHINE_EVENTS
        ).content.splitlines()
        self.assertLess(len(set(duplicate_rows)), len(duplicate_rows))

        ordering = self.bundle(
            "cyclic-bounded", "until-terminal", "symlinks-ordering"
        )
        order_rows = _input(
            ordering.definition, retry.BOUNDED_RETRY_STATE_MACHINE_EVENTS
        ).content.splitlines()
        self.assertNotEqual(order_rows, sorted(order_rows))
        self.assertTrue(
            any(type(item) is InputSymlink for item in ordering.definition.inputs)
        )

        partial = self.bundle("linear", "fixed-four", "partial-permissions")
        events = _input(
            partial.definition, retry.BOUNDED_RETRY_STATE_MACHINE_EVENTS
        )
        self.assertEqual(events.mode, 0o400)
        self.assertTrue(
            any(
                type(item) is InputFile and item.mode == 0o000
                for item in partial.definition.inputs
            )
        )

    def test_output_verifier_kills_attempt_terminal_and_exact_type_mutants(self) -> None:
        task = self.task("linear", "fixed-four")
        bundle = self.bundle("linear", "fixed-four", "spaces-unicode")
        primary = retry.derive_bounded_retry_state_machine_output(
            bundle.definition, task.parameters
        )
        attempt_mutants = (
            primary.attempts[:-1],
            b" " + primary.attempts,
            primary.attempts.replace(b"\tretry\n", b"\tfailed\n", 1),
            primary.attempts.replace(b"\t1\tprepare\t", b"\t2\tprepare\t", 1),
        )
        terminal_mutants = (
            primary.terminal[:-1],
            b" " + primary.terminal,
            primary.terminal.replace(b"\tcomplete\t", b"\tfailed\t", 1),
            primary.terminal.replace(b"\t9\t", b"\t8\t", 1),
        )
        for attempts in attempt_mutants:
            if attempts and not attempts.endswith(b"\n"):
                with self.assertRaises(retry.BoundedRetryStateMachineError):
                    retry.BoundedRetryStateMachineOutput(
                        attempts, primary.terminal
                    )
                continue
            candidate = retry.BoundedRetryStateMachineOutput(
                attempts, primary.terminal
            )
            self.assertFalse(
                retry.verify_bounded_retry_state_machine_output(
                    bundle.definition, task.parameters, candidate
                )
            )
        for terminal in terminal_mutants:
            if not terminal.endswith(b"\n"):
                with self.assertRaises(retry.BoundedRetryStateMachineError):
                    retry.BoundedRetryStateMachineOutput(primary.attempts, terminal)
                continue
            candidate = retry.BoundedRetryStateMachineOutput(
                primary.attempts, terminal
            )
            self.assertFalse(
                retry.verify_bounded_retry_state_machine_output(
                    bundle.definition, task.parameters, candidate
                )
            )
        self.assertFalse(
            retry.verify_bounded_retry_state_machine_output(
                bundle.definition, task.parameters, object()
            )
        )
        with self.assertRaises(retry.BoundedRetryStateMachineError):
            retry.BoundedRetryStateMachineOutput(
                _BytesSubclass(primary.attempts), primary.terminal
            )

    def test_independent_oracle_disagreement_fails_closed(self) -> None:
        task = self.task("linear", "fixed-four")
        profile = _profile("spaces-unicode")
        bundle = self.bundle("linear", "fixed-four", "spaces-unicode")
        primary = retry.derive_bounded_retry_state_machine_output(
            bundle.definition, task.parameters
        )
        divergent = retry.BoundedRetryStateMachineOutput(
            primary.attempts + b"x\n", primary.terminal
        )
        with mock.patch.object(
            retry,
            "reference_bounded_retry_state_machine_output",
            return_value=divergent,
        ):
            self.assertFalse(
                retry.verify_bounded_retry_state_machine_output(
                    bundle.definition, task.parameters, primary
                )
            )
            with self.assertRaises(retry.BoundedRetryStateMachineError):
                retry.build_bounded_retry_state_machine_fixture_bundle(
                    task, profile
                )

    def test_reference_oracle_does_not_depend_on_primary_semantic_helpers(self) -> None:
        task = self.task("cyclic-bounded", "until-terminal")
        bundle = self.bundle(
            "cyclic-bounded", "until-terminal", "symlinks-ordering"
        )
        expected = retry.reference_bounded_retry_state_machine_output(
            bundle.definition, task.parameters
        )
        primary_only_helpers = (
            "_events_bytes",
            "_decode_ascii",
            "_decode_detail",
            "_canonical_positive",
            "_validate_event_for_model",
            "_primary_parse_events",
            "_should_retry",
            "_failure_reason",
            "_primary_run_visit",
            "_terminal_from_failure",
            "_terminal_from_success",
            "_terminal_from_event",
            "_primary_simulate",
            "_attempts_bytes",
            "_terminal_bytes",
        )
        patches = [
            mock.patch.object(
                retry,
                helper,
                side_effect=AssertionError(f"primary helper {helper} was used"),
            )
            for helper in primary_only_helpers
        ]
        entered = []
        try:
            for patcher in patches:
                entered.append(patcher)
                patcher.start()
            observed = retry.reference_bounded_retry_state_machine_output(
                bundle.definition, task.parameters
            )
        finally:
            for patcher in reversed(entered):
                patcher.stop()
        self.assertEqual(observed, expected)
        self.assertEqual(observed.attempts, bundle.oracle.outputs[0].content)
        self.assertEqual(observed.terminal, bundle.oracle.outputs[1].content)

    def test_cross_task_profile_type_authority_and_hash_tampering_fail_closed(self) -> None:
        task = self.task("linear", "fixed-four")
        other_task = self.task("branching", "fixed-four")
        profile = _profile("spaces-unicode")
        other_profile = _profile("empty-duplicates")
        bundle = self.bundle("linear", "fixed-four", "spaces-unicode")
        self.assertFalse(
            retry.verify_bounded_retry_state_machine_fixture_for_task_profile(
                other_task, profile, bundle
            )
        )
        self.assertFalse(
            retry.verify_bounded_retry_state_machine_fixture_for_task_profile(
                task, other_profile, bundle
            )
        )
        self.assertFalse(
            retry.verify_bounded_retry_state_machine_fixture_bundle(object())
        )
        with self.assertRaises(retry.BoundedRetryStateMachineError):
            retry.BoundedRetryStateMachineParameters(
                _StringSubclass("linear"), "fixed-four"
            )
        with self.assertRaises(retry.BoundedRetryStateMachineError):
            retry.BoundedRetryStateMachineParameters(
                "linear", _StringSubclass("fixed-four")
            )
        for field_name in (
            "candidate_execution_authorized",
            "model_selection_eligible",
            "claim_authorized",
        ):
            with self.subTest(field=field_name), self.assertRaises(
                retry.BoundedRetryStateMachineError
            ):
                replace(bundle, **{field_name: True})
        with self.assertRaises(retry.BoundedRetryStateMachineError):
            replace(bundle, task_contract_sha256="0" * 64)
        with self.assertRaises(retry.BoundedRetryStateMachineError):
            replace(bundle, fixture_definition_sha256="0" * 64)
        with self.assertRaises(retry.BoundedRetryStateMachineError):
            replace(bundle.oracle, oracle_sha256="0" * 64)
        with self.assertRaises((retry.BoundedRetryStateMachineError, ValueError)):
            replace(bundle.descriptor, fixture_sha256="0" * 64)
        with self.assertRaises(retry.BoundedRetryStateMachineError):
            replace(task, public=False)
        with self.assertRaises(retry.BoundedRetryStateMachineError):
            replace(task, allowed_tools=("awk",))
        wrong_policy = replace(
            bundle.definition,
            expected_files=(
                ExpectedFile(
                    retry.BOUNDED_RETRY_STATE_MACHINE_ATTEMPTS_OUTPUT,
                    maximum_bytes=1,
                    mode=0o644,
                ),
                ExpectedFile(
                    retry.BOUNDED_RETRY_STATE_MACHINE_TERMINAL_OUTPUT,
                    maximum_bytes=64 * 1024,
                    mode=0o644,
                ),
            ),
        )
        with self.assertRaises(retry.BoundedRetryStateMachineError):
            retry.derive_bounded_retry_state_machine_output(
                wrong_policy, task.parameters
            )

    def test_randomized_row_order_and_identical_duplicates_keep_oracles_aligned(self) -> None:
        rng = random.Random(0xB0A6DED)
        for task in self.tasks:
            base = self.bundle(
                task.parameters.transition_model,
                task.parameters.retry_policy,
                "spaces-unicode",
            )
            content = _input(
                base.definition, retry.BOUNDED_RETRY_STATE_MACHINE_EVENTS
            ).content
            original_rows = content.splitlines(keepends=True)
            for iteration in range(10):
                rows = list(original_rows)
                rng.shuffle(rows)
                for _ in range(rng.randrange(0, 4)):
                    rows.insert(rng.randrange(len(rows) + 1), rng.choice(rows))
                definition = _replace_input(
                    base.definition,
                    retry.BOUNDED_RETRY_STATE_MACHINE_EVENTS,
                    content=b"".join(rows),
                )
                primary = retry.derive_bounded_retry_state_machine_output(
                    definition, task.parameters
                )
                reference = retry.reference_bounded_retry_state_machine_output(
                    definition, task.parameters
                )
                with self.subTest(
                    model=task.parameters.transition_model,
                    policy=task.parameters.retry_policy,
                    iteration=iteration,
                ):
                    self.assertEqual(primary, reference)
                    self.assertTrue(
                        retry.verify_bounded_retry_state_machine_output(
                            definition, task.parameters, primary
                        )
                    )

    def test_hash_seed_does_not_change_task_or_fixture_identities(self) -> None:
        script = """
from cbds.executable_bounded_retry_state_machine import (
    build_bounded_retry_state_machine_fixture_bundle,
    build_bounded_retry_state_machine_tasks,
)
from cbds.executable_fixture_profiles import PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
tasks = build_bounded_retry_state_machine_tasks()
print('|'.join(task.task_contract_sha256 for task in tasks))
print('|'.join(
    build_bounded_retry_state_machine_fixture_bundle(task, profile).descriptor.fixture_sha256
    for task in tasks for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
))
"""
        outputs = []
        for seed in ("0", "1", "17", "999"):
            environment = dict(os.environ)
            environment["PYTHONHASHSEED"] = seed
            environment["PYTHONPATH"] = str(ROOT / "src")
            completed = subprocess.run(
                [sys.executable, "-c", script],
                cwd=ROOT,
                env=environment,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            outputs.append(completed.stdout)
        self.assertEqual(len(set(outputs)), 1)

    def test_all_100_materializations_accept_exact_final_state(self) -> None:
        for task in self.tasks:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                bundle = self.by_pair[(task.task_id, profile.profile_id)]
                with self.subTest(
                    model=task.parameters.transition_model,
                    policy=task.parameters.retry_policy,
                    profile=profile.profile_id,
                ), tempfile.TemporaryDirectory() as temporary:
                    workspace = Path(temporary) / "workspace"
                    with retry.materialize_bounded_retry_state_machine_fixture(
                        task, profile, bundle, workspace
                    ) as handle:
                        self.assertFalse(
                            retry.verify_bounded_retry_state_machine_workspace(
                                task, profile, bundle, handle
                            )
                        )
                        _write_expected(workspace, bundle)
                        self.assertTrue(
                            retry.verify_bounded_retry_state_machine_workspace(
                                task, profile, bundle, handle
                            )
                        )

    def test_workspace_missing_extra_corrupt_symlink_mode_link_and_input_mutants_fail(self) -> None:
        task = self.task("linear", "fixed-four")
        profile = _profile("spaces-unicode")
        bundle = self.bundle("linear", "fixed-four", "spaces-unicode")
        events = _input(bundle.definition, retry.BOUNDED_RETRY_STATE_MACHINE_EVENTS)

        def run_mutation(name: str, mutate) -> None:
            with self.subTest(mutation=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                workspace = root / "workspace"
                with retry.materialize_bounded_retry_state_machine_fixture(
                    task, profile, bundle, workspace
                ) as handle:
                    _write_expected(workspace, bundle)
                    mutate(root, workspace)
                    self.assertFalse(
                        retry.verify_bounded_retry_state_machine_workspace(
                            task, profile, bundle, handle
                        )
                    )

        run_mutation(
            "corrupt-attempts",
            lambda _root, workspace: (
                workspace / retry.BOUNDED_RETRY_STATE_MACHINE_ATTEMPTS_OUTPUT
            ).write_bytes(bundle.oracle.outputs[0].content + b"x"),
        )
        run_mutation(
            "corrupt-terminal",
            lambda _root, workspace: (
                workspace / retry.BOUNDED_RETRY_STATE_MACHINE_TERMINAL_OUTPUT
            ).write_bytes(bundle.oracle.outputs[1].content[:-1]),
        )
        run_mutation(
            "extra-output",
            lambda _root, workspace: (workspace / "output" / "extra").write_bytes(b"x"),
        )
        run_mutation(
            "wrong-output-mode",
            lambda _root, workspace: os.chmod(
                workspace / retry.BOUNDED_RETRY_STATE_MACHINE_TERMINAL_OUTPUT,
                0o600,
            ),
        )
        run_mutation(
            "wrong-directory-mode",
            lambda _root, workspace: os.chmod(workspace / "output", 0o700),
        )
        run_mutation(
            "output-hardlink",
            lambda root, workspace: os.link(
                workspace / retry.BOUNDED_RETRY_STATE_MACHINE_TERMINAL_OUTPUT,
                root / "outside-link",
            ),
        )
        run_mutation(
            "input-content",
            lambda _root, workspace: (workspace / events.path).write_bytes(
                events.content + b"x"
            ),
        )
        run_mutation(
            "input-mode",
            lambda _root, workspace: os.chmod(workspace / events.path, 0o400),
        )
        run_mutation(
            "input-hardlink",
            lambda root, workspace: os.link(
                workspace / events.path, root / "outside-input-link"
            ),
        )
        run_mutation(
            "top-level-extra",
            lambda _root, workspace: (workspace / "extra").write_bytes(b"x"),
        )

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with retry.materialize_bounded_retry_state_machine_fixture(
                task, profile, bundle, workspace
            ) as handle:
                output = workspace / "output"
                output.mkdir(mode=0o755)
                os.symlink(
                    "../input/workflow/events.tsv",
                    output / "attempts.tsv",
                )
                (output / "terminal.tsv").write_bytes(bundle.oracle.outputs[1].content)
                os.chmod(output / "terminal.tsv", 0o644)
                self.assertFalse(
                    retry.verify_bounded_retry_state_machine_workspace(
                        task, profile, bundle, handle
                    )
                )

    def test_workspace_detects_input_mtime_and_symlink_target_mutation(self) -> None:
        task = self.task("linear", "fixed-four")
        profile = _profile("spaces-unicode")
        bundle = self.bundle("linear", "fixed-four", "spaces-unicode")
        events = _input(bundle.definition, retry.BOUNDED_RETRY_STATE_MACHINE_EVENTS)
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with retry.materialize_bounded_retry_state_machine_fixture(
                task, profile, bundle, workspace
            ) as handle:
                _write_expected(workspace, bundle)
                path = workspace / events.path
                observed = path.stat()
                os.utime(
                    path,
                    ns=(observed.st_atime_ns, observed.st_mtime_ns + 1_000_000),
                )
                self.assertFalse(
                    retry.verify_bounded_retry_state_machine_workspace(
                        task, profile, bundle, handle
                    )
                )

        link_task = self.task("linear", "fixed-four")
        link_profile = _profile("symlinks-ordering")
        link_bundle = self.bundle(
            "linear", "fixed-four", "symlinks-ordering"
        )
        link = next(
            item
            for item in link_bundle.definition.inputs
            if type(item) is InputSymlink
        )
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            with retry.materialize_bounded_retry_state_machine_fixture(
                link_task, link_profile, link_bundle, workspace
            ) as handle:
                _write_expected(workspace, link_bundle)
                path = workspace / link.path
                path.unlink()
                os.symlink("missing.tsv", path)
                self.assertFalse(
                    retry.verify_bounded_retry_state_machine_workspace(
                        link_task, link_profile, link_bundle, handle
                    )
                )

    def test_generation_and_verification_never_invoke_a_process(self) -> None:
        task = self.task("compensating", "fixed-four")
        profile = _profile("partial-permissions")
        bundle = self.bundle(
            "compensating", "fixed-four", "partial-permissions"
        )
        with mock.patch(
            "subprocess.run", side_effect=AssertionError("process launched")
        ), mock.patch(
            "subprocess.Popen", side_effect=AssertionError("process launched")
        ), mock.patch(
            "os.system", side_effect=AssertionError("process launched")
        ), mock.patch(
            "os.popen", side_effect=AssertionError("process launched")
        ):
            self.assertEqual(len(retry.build_bounded_retry_state_machine_tasks()), 20)
            rebuilt = retry.build_bounded_retry_state_machine_fixture_bundle(
                task, profile
            )
            self.assertEqual(rebuilt, bundle)
            primary = retry.derive_bounded_retry_state_machine_output(
                bundle.definition, task.parameters
            )
            self.assertTrue(
                retry.verify_bounded_retry_state_machine_output(
                    bundle.definition, task.parameters, primary
                )
            )

    def test_module_has_no_assert_subprocess_or_frozen_registry_write(self) -> None:
        source_path = (
            ROOT
            / "src"
            / "cbds"
            / "executable_bounded_retry_state_machine.py"
        )
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        self.assertNotIn("subprocess", imported)
        for predecessor in (
            "executable_static_registry",
            "executable_static_second_registry",
            "executable_static_third_registry",
            "executable_static_fourth_registry",
            "executable_static_fifth_registry",
        ):
            self.assertNotIn(predecessor, source)
        self.assertNotIn("candidate_execution_authorized=True", source)


if __name__ == "__main__":
    unittest.main()
