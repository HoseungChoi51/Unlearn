"""Fixed reviewed Bash feasibility canary for collision-safe batch rename.

The test executes only the source literal below.  It is not a caller-selected
candidate API, a production sandbox, scored evaluation, or evidence that an
arbitrary generated program is safe.  Its restricted PATH establishes that
this fixed program needs no undeclared external tool; it does not make the
final-state verifier an observer of rename, collision-decision, staging,
atomic-publication, crash, read-scope, tool, inode, or exit-status history.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_collision_safe_batch_rename as rename  # noqa: E402
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)


_HAND_AUTHORED_BASH = r"""
set -euo pipefail

export LC_ALL=C
umask 022

files_equal() {
    local left=$1 right=$2 left_size right_size index
    local -a left_segments=() right_segments=()

    left_size=$(stat -c '%s' -- "$left") || return 2
    right_size=$(stat -c '%s' -- "$right") || return 2
    [[ $left_size == "$right_size" ]] || return 1
    mapfile -d '' -t left_segments < "$left" || return 2
    mapfile -d '' -t right_segments < "$right" || return 2
    ((${#left_segments[@]} == ${#right_segments[@]})) || return 1
    for ((index = 0; index < ${#left_segments[@]}; index++)); do
        [[ ${left_segments[index]} == "${right_segments[index]}" ]] || return 1
    done
    return 0
}

if [[ ${1-} == --compare-files ]]; then
    (($# == 3)) || exit 64
    if files_equal "$2" "$3"; then
        exit 0
    else
        exit $?
    fi
fi

rename_rule=${1:?rename rule required}
collision_policy=${2:?collision policy required}
case $rename_rule in
    lowercase-basename|numbered-prefix|suffix-rewrite|manifest-mapping) ;;
    *) exit 65 ;;
esac
case $collision_policy in
    reject-all|skip-collisions|stable-first|stable-last|identical-files-coalesce) ;;
    *) exit 66 ;;
esac

candidate_root=input/rename/candidates
mapping_file=input/rename/mapping.tsv
stage=.cbds-fixed-rename-stage

mapfile -d '' -t candidates < <(
    find "$candidate_root" -type f -print0 | sort -z --
)
candidate_count=${#candidates[@]}

declare -A mapped_by_source=()
while IFS=$'\t' read -r relative destination extra; do
    [[ -n $relative && -n $destination && -z ${extra:-} ]]
    full_source=$candidate_root/$relative
    if [[ -n ${mapped_by_source[$full_source]+present} ]]; then
        [[ ${mapped_by_source[$full_source]} == "$destination" ]]
    else
        mapped_by_source["$full_source"]=$destination
    fi
done < "$mapping_file"

declare -A destination_by_source=()
declare -A rank_by_parent=()
for source in "${candidates[@]}"; do
    basename=${source##*/}
    case $rename_rule in
        lowercase-basename)
            destination=${basename,,}
            ;;
        numbered-prefix)
            parent=${source%/*}
            rank=$((${rank_by_parent[$parent]-0} + 1))
            rank_by_parent["$parent"]=$rank
            printf -v destination '%04d-%s' "$rank" "$basename"
            ;;
        suffix-rewrite)
            stem=${basename%.*}
            suffix=${basename##*.}
            if [[ $basename == *.* && -n $stem && -n $suffix ]]; then
                destination=$stem.ready
            else
                destination=$basename.ready
            fi
            ;;
        manifest-mapping)
            destination=${mapped_by_source[$source]}
            ;;
    esac
    destination_by_source["$source"]=$destination
done

declare -A group_count=()
declare -A group_members=()
destinations=()
for source in "${candidates[@]}"; do
    destination=${destination_by_source[$source]}
    if [[ -z ${group_count[$destination]+present} ]]; then
        group_count["$destination"]=0
        destinations+=("$destination")
    fi
    group_count["$destination"]=$((${group_count[$destination]} + 1))
    group_members["$destination"]+=$source$'\n'
done

sorted_destinations=()
if ((${#destinations[@]})); then
    mapfile -t sorted_destinations < <(
        printf '%s\n' "${destinations[@]}" | sort -u --
    )
fi

collision_groups=0
for destination in "${sorted_destinations[@]}"; do
    if ((${group_count[$destination]} > 1)); then
        collision_groups=$((collision_groups + 1))
    fi
done

state=complete
if [[ $collision_policy == reject-all && $collision_groups -gt 0 ]]; then
    state=rejected
fi

declare -A outcome_by_source=()
declare -A representative_by_source=()
declare -A group_size_by_source=()
declare -A move_members_by_destination=()

if [[ $state == rejected ]]; then
    for source in "${candidates[@]}"; do
        destination=${destination_by_source[$source]}
        outcome_by_source["$source"]=retained-rejected
        representative_by_source["$source"]=
        group_size_by_source["$source"]=${group_count[$destination]}
    done
else
    for destination in "${sorted_destinations[@]}"; do
        members=()
        mapfile -t members < <(
            printf '%s' "${group_members[$destination]}"
        )
        size=${#members[@]}
        if ((size == 1)); then
            winner=${members[0]}
            outcome_by_source["$winner"]=moved
            representative_by_source["$winner"]=$winner
            group_size_by_source["$winner"]=1
            move_members_by_destination["$destination"]=$winner$'\n'
            continue
        fi

        case $collision_policy in
            skip-collisions)
                for source in "${members[@]}"; do
                    outcome_by_source["$source"]=retained-collision
                    representative_by_source["$source"]=
                    group_size_by_source["$source"]=$size
                done
                ;;
            stable-first|stable-last)
                if [[ $collision_policy == stable-first ]]; then
                    winner=${members[0]}
                else
                    winner=${members[size - 1]}
                fi
                for source in "${members[@]}"; do
                    if [[ $source == "$winner" ]]; then
                        outcome_by_source["$source"]=moved
                    else
                        outcome_by_source["$source"]=retained-loser
                    fi
                    representative_by_source["$source"]=$winner
                    group_size_by_source["$source"]=$size
                done
                move_members_by_destination["$destination"]=$winner$'\n'
                ;;
            identical-files-coalesce)
                winner=${members[0]}
                all_identical=true
                for ((index = 1; index < size; index++)); do
                    if files_equal "$winner" "${members[index]}"; then
                        :
                    else
                        comparison_status=$?
                        ((comparison_status == 1)) || exit 67
                        all_identical=false
                        break
                    fi
                done
                if [[ $all_identical == true ]]; then
                    move_list=
                    for ((index = 1; index < size; index++)); do
                        source=${members[index]}
                        outcome_by_source["$source"]=coalesced
                        representative_by_source["$source"]=$winner
                        group_size_by_source["$source"]=$size
                        move_list+=$source$'\n'
                    done
                    outcome_by_source["$winner"]=moved
                    representative_by_source["$winner"]=$winner
                    group_size_by_source["$winner"]=$size
                    move_list+=$winner$'\n'
                    move_members_by_destination["$destination"]=$move_list
                else
                    for source in "${members[@]}"; do
                        outcome_by_source["$source"]=retained-nonidentical
                        representative_by_source["$source"]=
                        group_size_by_source["$source"]=$size
                    done
                fi
                ;;
            reject-all)
                exit 68
                ;;
        esac
    done
fi

destination_count=0
removed_count=0
for source in "${candidates[@]}"; do
    case ${outcome_by_source[$source]} in
        moved)
            destination_count=$((destination_count + 1))
            removed_count=$((removed_count + 1))
            ;;
        coalesced)
            removed_count=$((removed_count + 1))
            ;;
    esac
done
retained_count=$((candidate_count - removed_count))

[[ ! -e $stage && ! -L $stage ]]
mkdir -- "$stage"
if ((destination_count)); then
    mkdir -- "$stage/tree"
    for destination in "${sorted_destinations[@]}"; do
        [[ -n ${move_members_by_destination[$destination]-} ]] || continue
        moving=()
        mapfile -t moving < <(
            printf '%s' "${move_members_by_destination[$destination]}"
        )
        for source in "${moving[@]}"; do
            mv -f -- "$source" "$stage/tree/$destination"
        done
    done
fi

{
    printf 'batch\t%s\t%d\t%d\t%d\t%d\t%d\n' \
        "$state" "$candidate_count" "$collision_groups" \
        "$destination_count" "$removed_count" "$retained_count"
    for source in "${candidates[@]}"; do
        destination=${destination_by_source[$source]}
        printf 'file\t%s\t%s\t%s\t%s\t%d\n' \
            "${outcome_by_source[$source]}" "$source" "$destination" \
            "${representative_by_source[$source]}" \
            "${group_size_by_source[$source]}"
    done
} > "$stage/ledger.tsv"

mv -- "$stage" output
""".lstrip()


def _profile_by_id(profile_id: str):
    return next(
        profile
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        if profile.profile_id == profile_id
    )


def _binary_paths(test: unittest.TestCase) -> tuple[str, dict[str, str]]:
    if os.name != "posix":
        test.skipTest("the fixed rename Bash canary requires POSIX")
    bash = shutil.which("bash")
    if bash is None or not os.access(bash, os.X_OK):
        test.skipTest("bash is unavailable")
    feature_probe = subprocess.run(
        [
            bash,
            "--noprofile",
            "--norc",
            "-c",
            (
                "set -euo pipefail; "
                "declare -A probe=([key]=value); "
                "mapfile -t rows < /dev/null; "
                "value=ABC; [[ ${value,,} == abc ]]"
            ),
        ],
        env={"LANG": "C", "LC_ALL": "C", "PATH": "", "TZ": "UTC"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=5,
    )
    if feature_probe.returncode != 0:
        test.skipTest("bash lacks required associative-array/mapfile/case features")

    tools: dict[str, str] = {}
    for name in rename.COLLISION_SAFE_BATCH_RENAME_ALLOWED_TOOLS:
        path = shutil.which(name)
        if path is None or not os.access(path, os.X_OK):
            test.skipTest(f"required canary tool {name!r} is unavailable")
        tools[name] = path
    return bash, tools


def _write_fixed_canary(root: Path, tools: dict[str, str]) -> tuple[Path, Path]:
    tool_root = root / "allowed-tools"
    tool_root.mkdir(mode=0o700)
    for name, target in tools.items():
        os.symlink(Path(target).resolve(), tool_root / name)
    script = root / "fixed-collision-safe-rename-canary.bash"
    script.write_text(_HAND_AUTHORED_BASH, encoding="utf-8", newline="\n")
    script.chmod(0o400)
    return script, tool_root


def _run_fixed_canary(
    bash: str,
    script: Path,
    tool_root: Path,
    workspace: Path,
    *arguments: str,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [bash, "--noprofile", "--norc", str(script), *arguments],
        cwd=workspace,
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": str(tool_root),
            "TZ": "UTC",
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=20,
    )


class CollisionSafeBatchRenameBashCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = rename.build_collision_safe_batch_rename_tasks()

    def test_fixed_bash_canary_passes_all_twenty_cells_on_binary_profile(self) -> None:
        bash, tools = _binary_paths(self)
        self.assertEqual(len(self.tasks), 20)
        profile = _profile_by_id("empty-duplicates")
        observed_outcomes: set[str] = set()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, tool_root = _write_fixed_canary(root, tools)
            self.assertEqual(
                {item.name for item in tool_root.iterdir()},
                set(rename.COLLISION_SAFE_BATCH_RENAME_ALLOWED_TOOLS),
            )
            passed = 0
            for task_index, task in enumerate(self.tasks):
                bundle = rename.build_collision_safe_batch_rename_fixture_bundle(
                    task, profile
                )
                observed_outcomes.update(
                    action.outcome for action in bundle.oracle.actions
                )
                self.assertIs(task.candidate_execution_authorized, False)
                self.assertIs(task.model_selection_eligible, False)
                self.assertIs(task.claim_authorized, False)
                self.assertIs(bundle.candidate_execution_authorized, False)
                self.assertIs(bundle.model_selection_eligible, False)
                self.assertIs(bundle.claim_authorized, False)
                workspace = root / "workspaces" / f"cell-{task_index:02d}"
                with self.subTest(
                    rename_rule=task.parameters.rename_rule,
                    collision_policy=task.parameters.collision_policy,
                ), rename.materialize_collision_safe_batch_rename_fixture(
                    task, profile, bundle, workspace
                ) as handle:
                    completed = _run_fixed_canary(
                        bash,
                        script,
                        tool_root,
                        workspace,
                        task.parameters.rename_rule,
                        task.parameters.collision_policy,
                    )
                    self.assertEqual(
                        completed.returncode,
                        0,
                        completed.stdout + completed.stderr,
                    )
                    self.assertEqual(completed.stdout, b"")
                    self.assertEqual(completed.stderr, b"")
                    self.assertTrue(
                        rename.verify_collision_safe_batch_rename_workspace(
                            task, profile, bundle, handle
                        )
                    )
                    passed += 1
            self.assertEqual(passed, 20)
        self.assertEqual(
            observed_outcomes,
            {
                "moved",
                "retained-rejected",
                "retained-collision",
                "retained-loser",
                "coalesced",
                "retained-nonidentical",
            },
        )

    def test_mapfile_equality_is_exact_for_all_bytes_and_boundary_cases(self) -> None:
        bash, tools = _binary_paths(self)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, tool_root = _write_fixed_canary(root, tools)
            original = root / "all-bytes.bin"
            equal = root / "all-bytes-equal.bin"
            all_bytes = bytes(range(256))
            original.write_bytes(all_bytes)
            equal.write_bytes(all_bytes)
            completed = _run_fixed_canary(
                bash,
                script,
                tool_root,
                root,
                "--compare-files",
                str(original),
                str(equal),
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, b"")
            self.assertEqual(completed.stderr, b"")

            for index in range(256):
                near_miss = root / f"near-miss-{index:03d}.bin"
                changed = bytearray(all_bytes)
                changed[index] = (changed[index] + 1) % 256
                near_miss.write_bytes(changed)
                completed = _run_fixed_canary(
                    bash,
                    script,
                    tool_root,
                    root,
                    "--compare-files",
                    str(original),
                    str(near_miss),
                )
                with self.subTest(changed_byte=index):
                    self.assertEqual(completed.returncode, 1, completed.stderr)
                    self.assertEqual(completed.stdout, b"")
                    self.assertEqual(completed.stderr, b"")

            edge_cases = {
                "leading-nul": b"\x00abc",
                "consecutive-nul": b"a\x00\x00b",
                "trailing-nul": b"abc\x00",
                "repeated-trailing-nul": b"abc\x00\x00",
                "trailing-lf": b"abc\n",
                "empty": b"",
                "invalid-utf8": b"\xff\xfe\x80\x00x\n",
            }
            for name, payload in edge_cases.items():
                left = root / f"{name}.left"
                right = root / f"{name}.right"
                left.write_bytes(payload)
                right.write_bytes(payload)
                completed = _run_fixed_canary(
                    bash,
                    script,
                    tool_root,
                    root,
                    "--compare-files",
                    str(left),
                    str(right),
                )
                with self.subTest(equal_edge=name):
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertEqual(completed.stdout, b"")
                    self.assertEqual(completed.stderr, b"")

            unequal_pairs = (
                (b"\x00abc", b"abc\x00"),
                (b"a\x00\x00b", b"a\x00b\x00"),
                (b"abc\x00", b"abc\n"),
                (b"abc\n", b"abcX"),
                (b"abc\x00", b"abc\x00\x00"),
            )
            for index, (left_payload, right_payload) in enumerate(unequal_pairs):
                left = root / f"unequal-{index}.left"
                right = root / f"unequal-{index}.right"
                left.write_bytes(left_payload)
                right.write_bytes(right_payload)
                completed = _run_fixed_canary(
                    bash,
                    script,
                    tool_root,
                    root,
                    "--compare-files",
                    str(left),
                    str(right),
                )
                with self.subTest(unequal_edge=index):
                    self.assertEqual(completed.returncode, 1, completed.stderr)
                    self.assertEqual(completed.stdout, b"")
                    self.assertEqual(completed.stderr, b"")

    def test_canary_does_not_widen_authority_or_observation_claims(self) -> None:
        self.assertTrue(
            all(
                task.candidate_execution_authorized is False
                and task.model_selection_eligible is False
                and task.claim_authorized is False
                for task in self.tasks
            )
        )
        for value in (
            rename.COLLISION_SAFE_BATCH_RENAME_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
            rename.COLLISION_SAFE_BATCH_RENAME_RENAME_HISTORY_OBSERVED,
            rename.COLLISION_SAFE_BATCH_RENAME_ATOMIC_PUBLICATION_HISTORY_OBSERVED,
            rename.COLLISION_SAFE_BATCH_RENAME_CRASH_ATOMICITY_OBSERVED,
            rename.COLLISION_SAFE_BATCH_RENAME_INODE_IDENTITY_OBSERVED,
            rename.COLLISION_SAFE_BATCH_RENAME_COLLISION_DECISION_HISTORY_OBSERVED,
            rename.COLLISION_SAFE_BATCH_RENAME_READ_SCOPE_OBSERVED,
            rename.COLLISION_SAFE_BATCH_RENAME_TOOL_HISTORY_OBSERVED,
            rename.COLLISION_SAFE_BATCH_RENAME_TRANSIENT_INPUT_PRESERVATION_OBSERVED,
            rename.COLLISION_SAFE_BATCH_RENAME_CANDIDATE_EXIT_STATUS_OBSERVED,
        ):
            self.assertIs(value, False)
        self.assertIs(
            rename.COLLISION_SAFE_BATCH_RENAME_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE,
            True,
        )
        self.assertNotIn("/usr/bin/", _HAND_AUTHORED_BASH)
        self.assertNotIn("/bin/", _HAND_AUTHORED_BASH)
        self.assertIn("mapfile -d '' -t", _HAND_AUTHORED_BASH)
        self.assertIn("left_size=$(stat -c '%s'", _HAND_AUTHORED_BASH)


if __name__ == "__main__":
    unittest.main()
