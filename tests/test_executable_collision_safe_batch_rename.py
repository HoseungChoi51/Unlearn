from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import cbds.executable_collision_safe_batch_rename as rename
from cbds.executable_collision_safe_batch_rename import (
    COLLISION_SAFE_BATCH_RENAME_ALLOWED_TOOLS,
    COLLISION_SAFE_BATCH_RENAME_COLLISION_POLICIES,
    COLLISION_SAFE_BATCH_RENAME_FAMILY_ID,
    COLLISION_SAFE_BATCH_RENAME_RENAME_RULES,
    CollisionSafeBatchRenameAction,
    CollisionSafeBatchRenameError,
    CollisionSafeBatchRenameOracle,
    CollisionSafeBatchRenameParameters,
    build_collision_safe_batch_rename_fixture_bundle,
    build_collision_safe_batch_rename_tasks,
    derive_collision_safe_batch_rename_state,
    materialize_collision_safe_batch_rename_fixture,
    reference_collision_safe_batch_rename_state,
    verify_collision_safe_batch_rename_fixture_bundle,
    verify_collision_safe_batch_rename_fixture_for_task_profile,
    verify_collision_safe_batch_rename_state,
    verify_collision_safe_batch_rename_workspace,
)
from cbds.executable_fixture_bundle import OracleOutputRecord
from cbds.executable_fixture_profiles import PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
from cbds.executable_workspace import FixtureDefinition, InputFile, InputSymlink


def profile_by_id(profile_id: str):
    return next(
        profile
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        if profile.profile_id == profile_id
    )


def task_by_parameters(tasks, rule: str, policy: str):
    return next(
        task
        for task in tasks
        if task.parameters.rename_rule == rule
        and task.parameters.collision_policy == policy
    )


def _publish_exact_state(handle, bundle) -> None:
    """Simulate the prescribed final state while preserving source mtimes."""

    workspace = handle.workspace
    stage = workspace / ".rename-stage"
    stage.mkdir(mode=0o755)
    ledger = next(
        output
        for output in bundle.oracle.outputs
        if output.path == "output/ledger.tsv"
    )
    ledger_path = stage / "ledger.tsv"
    ledger_path.write_bytes(ledger.content)
    ledger_path.chmod(ledger.mode)

    by_output: dict[str, list[CollisionSafeBatchRenameAction]] = {}
    for action in bundle.oracle.actions:
        if action.outcome in {"moved", "coalesced"}:
            by_output.setdefault(action.output_path, []).append(action)
    for output_path in sorted(by_output, key=str.encode):
        actions = by_output[output_path]
        moved = next(action for action in actions if action.outcome == "moved")
        order = [
            action for action in actions if action.outcome == "coalesced"
        ] + [moved]
        relative = Path(output_path).relative_to("output")
        target = stage / relative
        target.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
        for action in order:
            os.replace(workspace / action.source, target)
    os.replace(stage, workspace / "output")


class CollisionSafeBatchRenameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = build_collision_safe_batch_rename_tasks()

    def test_exact_four_by_five_grid_and_public_metadata(self) -> None:
        self.assertEqual(len(self.tasks), 20)
        self.assertEqual(
            {
                (
                    task.parameters.rename_rule,
                    task.parameters.collision_policy,
                )
                for task in self.tasks
            },
            {
                (rule, policy)
                for rule in COLLISION_SAFE_BATCH_RENAME_RENAME_RULES
                for policy in COLLISION_SAFE_BATCH_RENAME_COLLISION_POLICIES
            },
        )
        self.assertEqual(len({task.task_id for task in self.tasks}), 20)
        self.assertEqual(
            len({task.task_contract_sha256 for task in self.tasks}), 20
        )
        for task in self.tasks:
            self.assertEqual(task.family_id, COLLISION_SAFE_BATCH_RENAME_FAMILY_ID)
            self.assertEqual(task.allowed_tools, COLLISION_SAFE_BATCH_RENAME_ALLOWED_TOOLS)
            self.assertEqual(task.filesystem_identity, "rename-candidate-tree")
            self.assertEqual(
                task.output_identity, "atomic-renamed-tree-and-ledger"
            )
            self.assertTrue(task.public)
            self.assertFalse(task.sealed)
            self.assertFalse(task.candidate_execution_authorized)
            self.assertFalse(task.model_selection_eligible)
            self.assertFalse(task.claim_authorized)
            self.assertEqual(len(task.fixtures), 5)
            task.__post_init__()
            self.assertEqual(
                task.to_public_record()["task_contract_sha256"],
                task.task_contract_sha256,
            )

    def test_task_rebuild_is_deterministic(self) -> None:
        rebuilt = build_collision_safe_batch_rename_tasks()
        self.assertEqual(rebuilt, self.tasks)

    def test_all_100_bundles_are_deterministic_dual_engine_bound(self) -> None:
        fixture_ids: set[str] = set()
        for task in self.tasks:
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                first = build_collision_safe_batch_rename_fixture_bundle(
                    task, profile
                )
                second = build_collision_safe_batch_rename_fixture_bundle(
                    task, profile
                )
                self.assertEqual(first, second)
                self.assertTrue(verify_collision_safe_batch_rename_fixture_bundle(first))
                self.assertTrue(
                    verify_collision_safe_batch_rename_fixture_for_task_profile(
                        task, profile, first
                    )
                )
                primary = derive_collision_safe_batch_rename_state(
                    first.definition, task.parameters
                )
                reference = reference_collision_safe_batch_rename_state(
                    first.definition, task.parameters
                )
                self.assertEqual(primary, reference)
                self.assertEqual(primary, (first.oracle.actions, first.oracle.outputs))
                self.assertTrue(
                    verify_collision_safe_batch_rename_state(
                        first.definition,
                        task.parameters,
                        first.oracle.actions,
                        first.oracle.outputs,
                    )
                )
                fixture_ids.add(first.descriptor.fixture_id)
        self.assertEqual(len(fixture_ids), 100)

    def test_rename_rules_are_exact_and_flat(self) -> None:
        profile = profile_by_id("spaces-unicode")
        lower = build_collision_safe_batch_rename_fixture_bundle(
            task_by_parameters(
                self.tasks, "lowercase-basename", "stable-first"
            ),
            profile,
        )
        by_source = {action.source: action for action in lower.oracle.actions}
        self.assertEqual(
            by_source[
                "input/rename/candidates/Alpha Space/ReadMe.TXT"
            ].destination,
            "readme.txt",
        )
        self.assertEqual(
            by_source["input/rename/candidates/unique/雪"].destination,
            "雪",
        )
        self.assertTrue(
            all(
                action.output_path == f"output/tree/{action.destination}"
                for action in lower.oracle.actions
            )
        )

        numbered = build_collision_safe_batch_rename_fixture_bundle(
            task_by_parameters(self.tasks, "numbered-prefix", "stable-first"),
            profile_by_id("symlinks-ordering"),
        )
        numbered_by_source = {
            action.source: action.destination
            for action in numbered.oracle.actions
        }
        self.assertEqual(
            numbered_by_source[
                "input/rename/candidates/ordered/Z-last.TXT"
            ],
            "0001-Z-last.TXT",
        )
        self.assertEqual(
            numbered_by_source[
                "input/rename/candidates/ordered/a-first.log"
            ],
            "0002-a-first.log",
        )
        self.assertEqual(
            numbered_by_source["input/rename/candidates/ordered/café.bin"],
            "0003-café.bin",
        )

    def test_suffix_edge_cases_and_manifest_duplicate_collapse(self) -> None:
        inputs = (
            InputFile(
                "input/rename/mapping.tsv",
                b".env\tmap-a\nname.\tmap-b\na.tar.gz\tmap-c\n",
                0o444,
            ),
            InputFile("input/rename/candidates/.env", b"a", 0o400),
            InputFile("input/rename/candidates/name.", b"b", 0o400),
            InputFile("input/rename/candidates/a.tar.gz", b"c", 0o400),
        )
        definition = FixtureDefinition("fixture.rename.edge-cases", inputs, ())
        actions, _outputs = derive_collision_safe_batch_rename_state(
            definition,
            CollisionSafeBatchRenameParameters(
                "suffix-rewrite", "skip-collisions"
            ),
        )
        self.assertEqual(
            {action.source.rsplit("/", 1)[-1]: action.destination for action in actions},
            {
                ".env": ".env.ready",
                "name.": "name..ready",
                "a.tar.gz": "a.tar.ready",
            },
        )

        duplicate_bundle = build_collision_safe_batch_rename_fixture_bundle(
            task_by_parameters(
                self.tasks, "manifest-mapping", "identical-files-coalesce"
            ),
            profile_by_id("empty-duplicates"),
        )
        mapping = next(
            item
            for item in duplicate_bundle.definition.inputs
            if type(item) is InputFile and item.path == "input/rename/mapping.tsv"
        )
        rows = mapping.content.splitlines()
        self.assertGreater(len(rows), len(set(rows)))
        self.assertEqual(
            derive_collision_safe_batch_rename_state(
                duplicate_bundle.definition,
                CollisionSafeBatchRenameParameters(
                    "manifest-mapping", "identical-files-coalesce"
                ),
            ),
            reference_collision_safe_batch_rename_state(
                duplicate_bundle.definition,
                CollisionSafeBatchRenameParameters(
                    "manifest-mapping", "identical-files-coalesce"
                ),
            ),
        )

    def test_collision_policies_have_exact_source_dispositions(self) -> None:
        profile = profile_by_id("spaces-unicode")
        states = {}
        for policy in COLLISION_SAFE_BATCH_RENAME_COLLISION_POLICIES:
            bundle = build_collision_safe_batch_rename_fixture_bundle(
                task_by_parameters(
                    self.tasks, "manifest-mapping", policy
                ),
                profile,
            )
            states[policy] = bundle

        reject = states["reject-all"]
        self.assertTrue(
            all(action.outcome == "retained-rejected" for action in reject.oracle.actions)
        )
        self.assertEqual(
            [output.path for output in reject.oracle.outputs],
            ["output/ledger.tsv"],
        )
        self.assertTrue(reject.oracle.outputs[0].content.startswith(b"batch\trejected\t"))

        skip = states["skip-collisions"]
        self.assertIn("moved", {action.outcome for action in skip.oracle.actions})
        self.assertIn(
            "retained-collision",
            {action.outcome for action in skip.oracle.actions},
        )

        first = states["stable-first"]
        last = states["stable-last"]
        first_winners = {
            action.destination: action.source
            for action in first.oracle.actions
            if action.outcome == "moved"
        }
        last_winners = {
            action.destination: action.source
            for action in last.oracle.actions
            if action.outcome == "moved"
        }
        self.assertNotEqual(first_winners, last_winners)
        self.assertIn("retained-loser", {a.outcome for a in first.oracle.actions})

        coalesced = states["identical-files-coalesce"]
        outcomes = {action.outcome for action in coalesced.oracle.actions}
        self.assertTrue(
            {"moved", "coalesced", "retained-nonidentical"}.issubset(outcomes)
        )
        dupe = [
            action
            for action in coalesced.oracle.actions
            if action.destination == "mapped dupe.bin"
        ]
        representative = min(
            (action.source for action in dupe), key=str.encode
        )
        self.assertEqual(
            {action.representative for action in dupe}, {representative}
        )
        self.assertEqual(
            [action.outcome for action in dupe].count("moved"), 1
        )
        self.assertEqual(
            [action.outcome for action in dupe].count("coalesced"), 1
        )

    def test_equal_size_different_bytes_do_not_coalesce(self) -> None:
        bundle = build_collision_safe_batch_rename_fixture_bundle(
            task_by_parameters(
                self.tasks,
                "manifest-mapping",
                "identical-files-coalesce",
            ),
            profile_by_id("empty-duplicates"),
        )
        equal_group = [
            action
            for action in bundle.oracle.actions
            if action.destination == "equal.out"
        ]
        self.assertEqual(len(equal_group), 2)
        self.assertEqual(
            {action.outcome for action in equal_group},
            {"retained-nonidentical"},
        )
        binary_group = [
            action
            for action in bundle.oracle.actions
            if action.destination == "binary.out"
        ]
        self.assertEqual(
            {action.outcome for action in binary_group},
            {"moved", "coalesced"},
        )
        output = next(
            output
            for output in bundle.oracle.outputs
            if output.path == "output/tree/binary.out"
        )
        self.assertEqual(output.content, bytes(range(256)))

    def test_collision_free_profile_exercises_reject_success_branch(self) -> None:
        for rule in COLLISION_SAFE_BATCH_RENAME_RENAME_RULES:
            bundle = build_collision_safe_batch_rename_fixture_bundle(
                task_by_parameters(self.tasks, rule, "reject-all"),
                profile_by_id("symlinks-ordering"),
            )
            self.assertTrue(
                all(action.outcome == "moved" for action in bundle.oracle.actions)
            )
            self.assertTrue(
                bundle.oracle.outputs[0].content.startswith(b"batch\tcomplete\t")
            )

    def test_profiles_cover_binary_names_symlinks_order_and_modes(self) -> None:
        task = task_by_parameters(
            self.tasks, "manifest-mapping", "identical-files-coalesce"
        )
        bundles = {
            profile.profile_id: build_collision_safe_batch_rename_fixture_bundle(
                task, profile
            )
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        }
        spaces = bundles["spaces-unicode"]
        self.assertTrue(
            any(
                " " in item.path or "雪" in item.path or "café" in item.path
                for item in spaces.definition.inputs
            )
        )
        globs = bundles["leading-dashes-globs"]
        self.assertTrue(
            any(
                any(character in item.path for character in "[]*?")
                for item in globs.definition.inputs
            )
        )
        symlinks = bundles["symlinks-ordering"]
        self.assertGreaterEqual(
            sum(type(item) is InputSymlink for item in symlinks.definition.inputs),
            2,
        )
        partial = bundles["partial-permissions"]
        modes = {
            item.mode for item in partial.definition.inputs if type(item) is InputFile
        }
        self.assertTrue({0o000, 0o400, 0o440, 0o500, 0o640, 0o750}.issubset(modes))

    def test_reference_engine_does_not_call_primary_semantic_helpers(self) -> None:
        task = task_by_parameters(
            self.tasks, "manifest-mapping", "identical-files-coalesce"
        )
        bundle = build_collision_safe_batch_rename_fixture_bundle(
            task, profile_by_id("empty-duplicates")
        )
        expected = reference_collision_safe_batch_rename_state(
            bundle.definition, task.parameters
        )
        with (
            mock.patch.object(rename, "_parse_primary", side_effect=AssertionError),
            mock.patch.object(
                rename, "_destinations_primary", side_effect=AssertionError
            ),
            mock.patch.object(
                rename, "_serialize_primary", side_effect=AssertionError
            ),
        ):
            self.assertEqual(
                reference_collision_safe_batch_rename_state(
                    bundle.definition, task.parameters
                ),
                expected,
            )

    def test_public_state_verifier_detects_forced_engine_disagreement(self) -> None:
        task = self.tasks[0]
        bundle = build_collision_safe_batch_rename_fixture_bundle(
            task, PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        )
        wrong = (
            bundle.oracle.actions,
            bundle.oracle.outputs[:-1],
        )
        with mock.patch.object(
            rename,
            "reference_collision_safe_batch_rename_state",
            return_value=wrong,
        ):
            self.assertFalse(
                verify_collision_safe_batch_rename_state(
                    bundle.definition,
                    task.parameters,
                    bundle.oracle.actions,
                    bundle.oracle.outputs,
                )
            )

    def test_mapping_domain_rejects_conflicts_missing_rows_and_bad_framing(self) -> None:
        task = task_by_parameters(
            self.tasks, "manifest-mapping", "stable-first"
        )
        bundle = build_collision_safe_batch_rename_fixture_bundle(
            task, profile_by_id("spaces-unicode")
        )
        mapping_index = next(
            index
            for index, item in enumerate(bundle.definition.inputs)
            if type(item) is InputFile and item.path == "input/rename/mapping.tsv"
        )
        mapping = bundle.definition.inputs[mapping_index]
        self.assertIs(type(mapping), InputFile)
        if type(mapping) is not InputFile:
            self.fail("mapping fixture leaf has the wrong exact type")
        first_row = mapping.content.splitlines()[0]
        source = first_row.split(b"\t", 1)[0]
        mutants = (
            mapping.content[:-1],
            mapping.content + source + b"\tconflicting-destination\n",
            b"\n".join(mapping.content.splitlines()[1:]) + b"\n",
            mapping.content + b"bad\ttoo\tmany\n",
        )
        for raw in mutants:
            inputs = list(bundle.definition.inputs)
            inputs[mapping_index] = InputFile(mapping.path, raw, mapping.mode)
            definition = FixtureDefinition(
                bundle.definition.fixture_id,
                tuple(inputs),
                (),
            )
            with self.assertRaises(CollisionSafeBatchRenameError):
                derive_collision_safe_batch_rename_state(
                    definition, task.parameters
                )
            with self.assertRaises(CollisionSafeBatchRenameError):
                reference_collision_safe_batch_rename_state(
                    definition, task.parameters
                )

    def test_action_and_oracle_tampering_fail_closed(self) -> None:
        task = task_by_parameters(
            self.tasks, "manifest-mapping", "stable-first"
        )
        bundle = build_collision_safe_batch_rename_fixture_bundle(
            task, profile_by_id("spaces-unicode")
        )
        first = bundle.oracle.actions[0]
        bad_action = replace(first, group_size=first.group_size + 1)
        actions = (bad_action,) + bundle.oracle.actions[1:]
        with self.assertRaises(CollisionSafeBatchRenameError):
            CollisionSafeBatchRenameOracle(
                actions,
                bundle.oracle.outputs,
                bundle.oracle.oracle_sha256,
            )
        output = bundle.oracle.outputs[0]
        outputs = (
            OracleOutputRecord(output.path, output.content + b"x", output.mode),
        ) + bundle.oracle.outputs[1:]
        with self.assertRaises(CollisionSafeBatchRenameError):
            CollisionSafeBatchRenameOracle(
                bundle.oracle.actions,
                outputs,
                bundle.oracle.oracle_sha256,
            )
        self.assertFalse(verify_collision_safe_batch_rename_fixture_bundle(None))
        self.assertFalse(
            verify_collision_safe_batch_rename_fixture_for_task_profile(
                task, profile_by_id("spaces-unicode"), None
            )
        )

    def test_string_subclasses_and_inconsistent_actions_fail_exact_types(self) -> None:
        class Text(str):
            pass

        task = task_by_parameters(
            self.tasks, "manifest-mapping", "stable-first"
        )
        profile = profile_by_id("spaces-unicode")
        bundle = build_collision_safe_batch_rename_fixture_bundle(task, profile)
        action = bundle.oracle.actions[0]
        with self.assertRaises(CollisionSafeBatchRenameError):
            replace(task, family_id=Text(task.family_id))
        with self.assertRaises(CollisionSafeBatchRenameError):
            replace(action, output_path=Text(action.output_path))
        with self.assertRaises(CollisionSafeBatchRenameError):
            replace(action, representative="")
        with self.assertRaises(CollisionSafeBatchRenameError):
            replace(
                bundle.oracle,
                semantic_verifier_identity=Text(
                    bundle.oracle.semantic_verifier_identity
                ),
            )
        with self.assertRaises(CollisionSafeBatchRenameError):
            replace(bundle, schema_version=Text(bundle.schema_version))

    def test_all_100_workspaces_accept_exact_move_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for task_index, task in enumerate(self.tasks):
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                    bundle = build_collision_safe_batch_rename_fixture_bundle(
                        task, profile
                    )
                    workspace = root / f"{task_index}-{profile.profile_id}"
                    with materialize_collision_safe_batch_rename_fixture(
                        task, profile, bundle, workspace
                    ) as handle:
                        _publish_exact_state(handle, bundle)
                        self.assertTrue(
                            verify_collision_safe_batch_rename_workspace(
                                task, profile, bundle, handle
                            ),
                            (task.parameters, profile.profile_id),
                        )

    def test_workspace_rejects_output_and_input_mutations(self) -> None:
        task = task_by_parameters(
            self.tasks, "manifest-mapping", "stable-first"
        )
        profile = profile_by_id("spaces-unicode")
        bundle = build_collision_safe_batch_rename_fixture_bundle(task, profile)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            workspace = root / "ledger"
            with materialize_collision_safe_batch_rename_fixture(
                task, profile, bundle, workspace
            ) as handle:
                _publish_exact_state(handle, bundle)
                ledger = workspace / "output/ledger.tsv"
                ledger.write_bytes(ledger.read_bytes() + b"x")
                self.assertFalse(
                    verify_collision_safe_batch_rename_workspace(
                        task, profile, bundle, handle
                    )
                )

            workspace = root / "mtime"
            with materialize_collision_safe_batch_rename_fixture(
                task, profile, bundle, workspace
            ) as handle:
                _publish_exact_state(handle, bundle)
                moved = next(
                    action
                    for action in bundle.oracle.actions
                    if action.outcome == "moved"
                )
                target = workspace / moved.output_path
                metadata = target.stat()
                os.utime(
                    target,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000),
                )
                self.assertFalse(
                    verify_collision_safe_batch_rename_workspace(
                        task, profile, bundle, handle
                    )
                )

            workspace = root / "retained"
            with materialize_collision_safe_batch_rename_fixture(
                task, profile, bundle, workspace
            ) as handle:
                _publish_exact_state(handle, bundle)
                retained = next(
                    action
                    for action in bundle.oracle.actions
                    if action.outcome == "retained-loser"
                )
                source = workspace / retained.source
                source.chmod(source.stat().st_mode & 0o777 ^ 0o100)
                self.assertFalse(
                    verify_collision_safe_batch_rename_workspace(
                        task, profile, bundle, handle
                    )
                )

            workspace = root / "leftover"
            with materialize_collision_safe_batch_rename_fixture(
                task, profile, bundle, workspace
            ) as handle:
                _publish_exact_state(handle, bundle)
                (workspace / ".leftover-stage").mkdir()
                self.assertFalse(
                    verify_collision_safe_batch_rename_workspace(
                        task, profile, bundle, handle
                    )
                )

            workspace = root / "restored"
            with materialize_collision_safe_batch_rename_fixture(
                task, profile, bundle, workspace
            ) as handle:
                _publish_exact_state(handle, bundle)
                moved = next(
                    action
                    for action in bundle.oracle.actions
                    if action.outcome == "moved"
                )
                original = next(
                    item
                    for item in bundle.definition.inputs
                    if type(item) is InputFile and item.path == moved.source
                )
                restored = workspace / moved.source
                restored.write_bytes(original.content)
                restored.chmod(original.mode)
                self.assertFalse(
                    verify_collision_safe_batch_rename_workspace(
                        task, profile, bundle, handle
                    )
                )

    def test_bundle_construction_starts_no_process(self) -> None:
        with (
            mock.patch.object(os, "system", side_effect=AssertionError),
            mock.patch.object(os, "spawnv", side_effect=AssertionError),
            mock.patch.object(os, "execv", side_effect=AssertionError),
        ):
            tasks = build_collision_safe_batch_rename_tasks()
            build_collision_safe_batch_rename_fixture_bundle(
                tasks[0], PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
            )

    def test_honest_claim_boundaries_are_explicit(self) -> None:
        false_names = (
            "COLLISION_SAFE_BATCH_RENAME_DIRECTORY_PERMISSION_ERRORS_COVERED",
            "COLLISION_SAFE_BATCH_RENAME_EFFECTIVE_ACCESS_FAILURES_COVERED",
            "COLLISION_SAFE_BATCH_RENAME_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE",
            "COLLISION_SAFE_BATCH_RENAME_RENAME_HISTORY_OBSERVED",
            "COLLISION_SAFE_BATCH_RENAME_ATOMIC_PUBLICATION_HISTORY_OBSERVED",
            "COLLISION_SAFE_BATCH_RENAME_CRASH_ATOMICITY_OBSERVED",
            "COLLISION_SAFE_BATCH_RENAME_INODE_IDENTITY_OBSERVED",
            "COLLISION_SAFE_BATCH_RENAME_COLLISION_DECISION_HISTORY_OBSERVED",
            "COLLISION_SAFE_BATCH_RENAME_READ_SCOPE_OBSERVED",
            "COLLISION_SAFE_BATCH_RENAME_TOOL_HISTORY_OBSERVED",
            "COLLISION_SAFE_BATCH_RENAME_TRANSIENT_INPUT_PRESERVATION_OBSERVED",
            "COLLISION_SAFE_BATCH_RENAME_CANDIDATE_EXIT_STATUS_OBSERVED",
        )
        for name in false_names:
            self.assertIs(getattr(rename, name), False, name)
        self.assertIs(
            rename.COLLISION_SAFE_BATCH_RENAME_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE,
            True,
        )
        self.assertIs(
            rename.COLLISION_SAFE_BATCH_RENAME_SYMLINK_DISTRACTORS_COVERED,
            True,
        )
        self.assertIs(
            rename.COLLISION_SAFE_BATCH_RENAME_MODE_UNREADABLE_UNLISTED_LEAVES_COVERED,
            True,
        )


if __name__ == "__main__":
    unittest.main()
