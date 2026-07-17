"""Fixed reviewed Bash canary for hardlink-deduplicated mirrors.

Only the source literal below is executed.  This is a public-development
feasibility check, not a caller-selected candidate API, production sandbox,
scored evaluation, model-selection input, or research claim.  Its restricted
PATH demonstrates that this one reviewed program uses only the family's exact
external-tool allowlist.  Final-state verification still does not observe
creation history, transient paths, tool history, global quiescence, or the
candidate's exit status.
"""

from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_hardlink_deduplicated_mirror as mirror  # noqa: E402
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)


_HAND_AUTHORED_BASH = r"""
set -euo pipefail

export LC_ALL=C
umask 022

equivalence_key=${1:?equivalence key required}
owner_policy=${2:?owner policy required}
case $equivalence_key in
    sha256|mode-and-sha256|suffix-and-sha256|declared-group-and-sha256) ;;
    *) exit 64 ;;
esac
case $owner_policy in
    smallest-path|largest-path|oldest-mtime|newest-mtime|manifest-priority) ;;
    *) exit 65 ;;
esac

declare -A declared_by_relative=()
declare -A priority_by_relative=()
manifest_count=0
while IFS= read -r -d '' relative; do
    IFS= read -r -d '' declared_group
    IFS= read -r -d '' priority
    [[ -n $relative && -n $declared_group && $priority =~ ^(0|[1-9][0-9]*)$ ]]
    [[ -z ${declared_by_relative["$relative"]+present} ]]
    declared_by_relative["$relative"]=$declared_group
    priority_by_relative["$relative"]=$priority
    ((manifest_count += 1))
done < input/metadata.nul

mapfile -d '' -t candidates < <(
    find input/source -type f -printf '%P\0' | sort -z --
)
candidate_count=${#candidates[@]}
((candidate_count > 0 && candidate_count == manifest_count))

declare -A content_sha_by_relative=()
declare -A mode_by_relative=()
declare -A mtime_by_relative=()
declare -A key_by_relative=()
declare -A members_by_key=()
declare -A size_by_key=()
keys=()

for relative in "${candidates[@]}"; do
    [[ -n ${declared_by_relative["$relative"]+present} ]]
    source=input/source/$relative
    IFS= read -r -d ' ' content_sha < <(sha256sum -z -- "$source")
    mode=$(stat -c '%a' -- "$source")
    mtime=$(stat -c '%Y' -- "$source")
    content_sha_by_relative["$relative"]=$content_sha
    mode_by_relative["$relative"]=$mode
    mtime_by_relative["$relative"]=$mtime

    case $equivalence_key in
        sha256)
            group_key=sha256:$content_sha
            ;;
        mode-and-sha256)
            group_key=mode:$mode:$content_sha
            ;;
        suffix-and-sha256)
            basename=${relative##*/}
            suffix=
            if [[ $basename == ?*.* ]]; then
                suffix=.${basename##*.}
            fi
            group_key=suffix:${#suffix}:$suffix:$content_sha
            ;;
        declared-group-and-sha256)
            declared_group=${declared_by_relative["$relative"]}
            group_key=declared:${#declared_group}:$declared_group:$content_sha
            ;;
    esac
    key_by_relative["$relative"]=$group_key
    if [[ -z ${size_by_key["$group_key"]+present} ]]; then
        size_by_key["$group_key"]=0
        members_by_key["$group_key"]=
        keys+=("$group_key")
    fi
    size_by_key["$group_key"]=$((${size_by_key["$group_key"]} + 1))
    members_by_key["$group_key"]+=$relative$'\n'
done

((${#declared_by_relative[@]} == candidate_count))

declare -A owner_by_relative=()
declare -A group_sha_by_relative=()
declare -A group_size_by_relative=()

mkdir -p -- output/tree
for group_key in "${keys[@]}"; do
    members=()
    mapfile -t members < <(printf '%s' "${members_by_key["$group_key"]}")
    group_size=${#members[@]}
    ((group_size == ${size_by_key["$group_key"]}))

    owner=${members[0]}
    case $owner_policy in
        smallest-path)
            ;;
        largest-path)
            owner=${members[group_size - 1]}
            ;;
        oldest-mtime)
            for member in "${members[@]:1}"; do
                if ((
                    ${mtime_by_relative["$member"]}
                    < ${mtime_by_relative["$owner"]}
                )); then
                    owner=$member
                fi
            done
            ;;
        newest-mtime)
            for member in "${members[@]:1}"; do
                if ((
                    ${mtime_by_relative["$member"]}
                    > ${mtime_by_relative["$owner"]}
                )); then
                    owner=$member
                fi
            done
            ;;
        manifest-priority)
            for member in "${members[@]:1}"; do
                if ((
                    ${priority_by_relative["$member"]}
                    < ${priority_by_relative["$owner"]}
                )); then
                    owner=$member
                fi
            done
            ;;
    esac

    IFS=' ' read -r semantic_group_sha _ < <(
        {
            printf 'cbds-hardlink-group-v2\0%s\0' "$equivalence_key"
            printf '%s\0' "${members[@]}"
        } | sha256sum
    )

    anchor=${members[0]}
    anchor_output=output/tree/$anchor
    mkdir -p -- "${anchor_output%/*}"
    cp -p -- "input/source/$owner" "$anchor_output"
    for member in "${members[@]:1}"; do
        member_output=output/tree/$member
        mkdir -p -- "${member_output%/*}"
        ln -- "$anchor_output" "$member_output"
    done

    for member in "${members[@]}"; do
        owner_by_relative["$member"]=$owner
        group_sha_by_relative["$member"]=$semantic_group_sha
        group_size_by_relative["$member"]=$group_size
    done
done

group_count=${#keys[@]}
saved_inode_count=$((candidate_count - group_count))
{
    printf 'mirror\t%d\t%d\t%d\n' \
        "$candidate_count" "$group_count" "$saved_inode_count"
    for relative in "${candidates[@]}"; do
        printf 'file\t%s\t%s\t%s\t%d\n' \
            "$relative" \
            "${owner_by_relative["$relative"]}" \
            "${group_sha_by_relative["$relative"]}" \
            "${group_size_by_relative["$relative"]}"
    done
} > output/ledger.tsv
""".lstrip()


def _binary_paths(
    test: unittest.TestCase | None = None,
) -> tuple[str, dict[str, str]]:
    def unavailable(message: str) -> None:
        if test is None:
            raise RuntimeError(message)
        test.skipTest(message)

    if os.name != "posix":
        unavailable("the fixed hardlink Bash canary requires POSIX")
    bash = shutil.which("bash")
    if bash is None or not os.access(bash, os.X_OK):
        unavailable("bash is unavailable")
        raise AssertionError("unreachable")
    feature_probe = subprocess.run(
        [
            bash,
            "--noprofile",
            "--norc",
            "-c",
            (
                "set -euo pipefail; "
                "declare -A probe=([key]=value); "
                "mapfile -d '' -t rows < /dev/null; "
                "[[ ${probe[key]} == value ]]"
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
        unavailable("bash lacks required associative-array/mapfile features")

    tools: dict[str, str] = {}
    for name in mirror.HARDLINK_DEDUPLICATED_MIRROR_ALLOWED_TOOLS:
        path = shutil.which(name)
        if path is None or not os.access(path, os.X_OK):
            unavailable(f"required canary tool {name!r} is unavailable")
            raise AssertionError("unreachable")
        tools[name] = path
    return bash, tools


def _write_fixed_canary(
    root: Path,
    tools: dict[str, str],
) -> tuple[Path, Path]:
    tool_root = root / "allowed-tools"
    tool_root.mkdir(mode=0o700)
    for name, target in tools.items():
        os.symlink(Path(target).resolve(), tool_root / name)
    script = root / "fixed-hardlink-deduplicated-mirror-canary.bash"
    script.write_text(_HAND_AUTHORED_BASH, encoding="utf-8", newline="\n")
    script.chmod(0o400)
    return script, tool_root


def _run_fixed_canary(
    bash: str,
    script: Path,
    tool_root: Path,
    workspace: Path,
    equivalence_key: str,
    owner_policy: str,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            bash,
            "--noprofile",
            "--norc",
            str(script),
            equivalence_key,
            owner_policy,
        ],
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


def _run_one_materialization_probe() -> None:
    bash, tools = _binary_paths()
    tasks = mirror.build_hardlink_deduplicated_mirror_tasks()
    task = next(
        item
        for item in tasks
        if item.parameters.equivalence_key == "declared-group-and-sha256"
        and item.parameters.owner_policy == "newest-mtime"
    )
    profile = next(
        item
        for item in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        if item.profile_id == "symlinks-ordering"
    )
    bundle = mirror.build_hardlink_deduplicated_mirror_fixture_bundle(
        task, profile
    )
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        script, tool_root = _write_fixed_canary(root, tools)
        workspace = root / "workspace"
        with mirror.materialize_hardlink_deduplicated_mirror_fixture(
            task,
            profile,
            bundle,
            workspace,
        ) as handle:
            completed = _run_fixed_canary(
                bash,
                script,
                tool_root,
                workspace,
                task.parameters.equivalence_key,
                task.parameters.owner_policy,
            )
            if (
                completed.returncode != 0
                or completed.stdout
                or completed.stderr
                or not mirror.verify_hardlink_deduplicated_mirror_workspace(
                    task,
                    profile,
                    bundle,
                    handle,
                )
            ):
                raise RuntimeError(
                    "reviewed Bash optimization probe failed: "
                    + (completed.stdout + completed.stderr).decode(
                        "utf-8", errors="replace"
                    )
                )


class HardlinkDeduplicatedMirrorBashCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = mirror.build_hardlink_deduplicated_mirror_tasks()

    def test_fixed_canary_passes_all_twenty_cells_and_five_profiles(
        self,
    ) -> None:
        bash, tools = _binary_paths(self)
        self.assertEqual(len(self.tasks), 20)
        self.assertEqual(len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES), 5)
        self.assertEqual(
            {profile.profile_id for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES},
            {
                "spaces-unicode",
                "leading-dashes-globs",
                "empty-duplicates",
                "symlinks-ordering",
                "partial-permissions",
            },
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, tool_root = _write_fixed_canary(root, tools)
            self.assertEqual(
                {item.name for item in tool_root.iterdir()},
                set(mirror.HARDLINK_DEDUPLICATED_MIRROR_ALLOWED_TOOLS),
            )
            passed = 0
            for task_index, task in enumerate(self.tasks):
                self.assertIs(task.candidate_execution_authorized, False)
                self.assertIs(task.model_selection_eligible, False)
                self.assertIs(task.claim_authorized, False)
                for profile_index, profile in enumerate(
                    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
                ):
                    bundle = (
                        mirror.build_hardlink_deduplicated_mirror_fixture_bundle(
                            task, profile
                        )
                    )
                    workspace = (
                        root
                        / "workspaces"
                        / f"{task_index:02d}-{profile_index}"
                    )
                    with self.subTest(
                        equivalence_key=task.parameters.equivalence_key,
                        owner_policy=task.parameters.owner_policy,
                        profile=profile.profile_id,
                    ), mirror.materialize_hardlink_deduplicated_mirror_fixture(
                        task,
                        profile,
                        bundle,
                        workspace,
                    ) as handle:
                        completed = _run_fixed_canary(
                            bash,
                            script,
                            tool_root,
                            workspace,
                            task.parameters.equivalence_key,
                            task.parameters.owner_policy,
                        )
                        self.assertEqual(
                            completed.returncode,
                            0,
                            completed.stdout + completed.stderr,
                        )
                        self.assertEqual(completed.stdout, b"")
                        self.assertEqual(completed.stderr, b"")
                        self.assertTrue(
                            mirror.verify_hardlink_deduplicated_mirror_workspace(
                                task,
                                profile,
                                bundle,
                                handle,
                            )
                        )
                        self.assertIs(
                            bundle.candidate_execution_authorized,
                            False,
                        )
                        self.assertIs(bundle.model_selection_eligible, False)
                        self.assertIs(bundle.claim_authorized, False)
                        passed += 1
            self.assertEqual(passed, 100)

    def test_materialization_and_verification_survive_opposite_optimization(
        self,
    ) -> None:
        _binary_paths(self)
        opposite = ("-O",) if sys.flags.optimize == 0 else ()
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.pathsep.join(
            (str(ROOT), str(ROOT / "src"))
        )
        script = (
            "from tests."
            "test_executable_hardlink_deduplicated_mirror_bash_canary "
            "import _run_one_materialization_probe; "
            "_run_one_materialization_probe()"
        )
        completed = subprocess.run(
            [sys.executable, *opposite, "-c", script],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=180,
        )
        self.assertEqual(
            completed.returncode,
            0,
            completed.stdout + completed.stderr,
        )
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"")

    def test_canary_remains_nonclaiming_and_uses_the_exact_tool_budget(
        self,
    ) -> None:
        self.assertEqual(
            mirror.HARDLINK_DEDUPLICATED_MIRROR_ALLOWED_TOOLS,
            ("cp", "find", "ln", "mkdir", "sha256sum", "sort", "stat"),
        )
        self.assertTrue(
            all(
                task.candidate_execution_authorized is False
                and task.model_selection_eligible is False
                and task.claim_authorized is False
                for task in self.tasks
            )
        )
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
            self.assertIs(profile.candidate_execution_authorized, False)
            self.assertIs(profile.model_selection_eligible, False)
            self.assertIs(profile.claim_authorized, False)

        self.assertIs(
            mirror.HARDLINK_DEDUPLICATED_MIRROR_INPUT_HARDLINKS_COVERED,
            True,
        )
        self.assertIs(
            mirror.HARDLINK_DEDUPLICATED_MIRROR_OUTPUT_HARDLINK_TOPOLOGY_OBSERVED,
            True,
        )
        self.assertIs(
            mirror.HARDLINK_DEDUPLICATED_MIRROR_SOURCE_MTIME_COMMITTED,
            True,
        )
        self.assertIs(
            mirror.HARDLINK_DEDUPLICATED_MIRROR_SYMLINK_DISTRACTORS_COVERED,
            True,
        )
        self.assertIs(
            mirror.HARDLINK_DEDUPLICATED_MIRROR_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE,
            True,
        )
        for value in (
            mirror.HARDLINK_DEDUPLICATED_MIRROR_DIRECTORY_PERMISSION_ERRORS_COVERED,
            mirror.HARDLINK_DEDUPLICATED_MIRROR_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
            mirror.HARDLINK_DEDUPLICATED_MIRROR_CREATION_HISTORY_OBSERVED,
            mirror.HARDLINK_DEDUPLICATED_MIRROR_TOOL_HISTORY_OBSERVED,
            mirror.HARDLINK_DEDUPLICATED_MIRROR_CANDIDATE_EXIT_STATUS_OBSERVED,
        ):
            self.assertIs(value, False)

        self.assertNotIn("/usr/bin/", _HAND_AUTHORED_BASH)
        self.assertNotIn("/bin/", _HAND_AUTHORED_BASH)
        self.assertNotIn("python", _HAND_AUTHORED_BASH)
        self.assertNotIn("perl", _HAND_AUTHORED_BASH)
        self.assertNotIn("touch ", _HAND_AUTHORED_BASH)
        self.assertNotIn("chmod ", _HAND_AUTHORED_BASH)
        self.assertIn("mapfile -d '' -t candidates", _HAND_AUTHORED_BASH)
        self.assertIn("sha256sum -z --", _HAND_AUTHORED_BASH)
        self.assertIn("cp -p --", _HAND_AUTHORED_BASH)
        self.assertIn("ln --", _HAND_AUTHORED_BASH)
        self.assertEqual(
            sha256(_HAND_AUTHORED_BASH.encode("utf-8")).hexdigest(),
            "88ce09de675c7aea80a523554d18fe4db072bc23102dc358c227cc6e29cbc760",
        )


if __name__ == "__main__":
    unittest.main()
