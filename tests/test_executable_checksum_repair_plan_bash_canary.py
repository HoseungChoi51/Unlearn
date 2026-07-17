"""Fixed reviewed Bash feasibility canary for checksum repair plans.

Only the literal below is executed.  It is public method-development
feasibility evidence for one reviewed program, not a caller-selected candidate
API, production sandbox, scored evaluation, model-selection input, or research
claim.  The restricted PATH demonstrates only that this literal uses the
family's exact external-tool budget.  Final-state verification does not prove
tool history, transient behavior, global quiescence, or candidate exit status.
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

import cbds.executable_checksum_repair_plan as repair  # noqa: E402
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)


_HAND_AUTHORED_BASH = r"""
set -euo pipefail

export LC_ALL=C
export TZ=UTC
umask 022
unset AWKLIBPATH AWKPATH JQ_COLORS POSIXLY_CORRECT

manifest_layout=${1:?manifest layout required}
repair_policy=${2:?repair policy required}
case $manifest_layout in
    sha256sum-text|jsonl|csv|nul-pairs) ;;
    *) exit 64 ;;
esac
case $repair_policy in
    report-only|replace-digest|drop-missing|quarantine-mismatch|strict-reject) ;;
    *) exit 65 ;;
esac

manifest=input/manifest.data
asset_root=input/assets
output_path=output/repair-plan.jsonl
separator=$'\x1f'

paths=()
declared_digests=()

valid_path() {
    local value=$1
    local component
    local components=()
    [[ -n $value ]] || return 1
    [[ $value != /* && $value != */ && $value != *//* ]] || return 1
    [[ $value != *\\* ]] || return 1
    [[ ! $value =~ [[:cntrl:]] ]] || return 1
    ((${#value} <= 4096)) || return 1
    IFS=/ read -r -a components <<< "$value"
    ((${#components[@]} > 0)) || return 1
    for component in "${components[@]}"; do
        [[ -n $component && $component != . && $component != .. ]] || return 1
        ((${#component} <= 255)) || return 1
    done
}

valid_digest() {
    [[ $1 =~ ^[0-9a-f]{64}$ ]]
}

append_record() {
    local path=$1
    local digest=$2
    valid_path "$path" || exit 66
    valid_digest "$digest" || exit 66
    paths+=("$path")
    declared_digests+=("$digest")
}

parse_sha256sum_text() {
    local line
    local digest
    local path
    while :; do
        line=
        if IFS= read -r line; then
            ((${#line} >= 67)) || exit 66
            digest=${line:0:64}
            [[ ${line:64:2} == "  " ]] || exit 66
            path=${line:66}
            append_record "$path" "$digest"
        else
            [[ -z $line ]] || exit 66
            break
        fi
    done < "$manifest"
}

parse_jsonl() {
    local line
    local key_text
    local value_text
    local keys
    local values
    while :; do
        line=
        if IFS= read -r line; then
            [[ -n $line ]] || exit 66
            [[ $line != *$'\r'* ]] || exit 66
            key_text=$(
                jq --stream -er '
                    select(length == 2)
                    | .[0]
                    | if length == 1 and (.[0] | type) == "string"
                      then .[0]
                      else error("nested JSON member")
                      end
                ' <<< "$line"
            ) || exit 66
            keys=()
            mapfile -t keys <<< "$key_text"
            ((${#keys[@]} == 2)) || exit 66
            [[ (
                ${keys[0]} == path && ${keys[1]} == sha256
            ) || (
                ${keys[0]} == sha256 && ${keys[1]} == path
            ) ]] || exit 66

            value_text=$(
                jq -er '
                    if type == "object"
                       and keys == ["path", "sha256"]
                       and (.path | type) == "string"
                       and (.sha256 | type) == "string"
                    then .path, .sha256
                    else error("invalid JSON checksum record")
                    end
                ' <<< "$line"
            ) || exit 66
            values=()
            mapfile -t values <<< "$value_text"
            ((${#values[@]} == 2)) || exit 66
            append_record "${values[0]}" "${values[1]}"
        else
            [[ -z $line ]] || exit 66
            break
        fi
    done < "$manifest"
}

validate_csv_crlf() {
    local line
    while :; do
        line=
        if IFS= read -r line; then
            [[ $line == *$'\r' ]] || exit 66
        else
            [[ -z $line ]] || exit 66
            break
        fi
    done < "$manifest"
}

parse_csv() {
    local row
    local rows
    local fields
    local final
    validate_csv_crlf
    rows=()
    mapfile -t rows < <(
        awk -v separator="$separator" '
            function fail() {
                failed = 1
                exit 66
            }
            function parse_csv_record(line, fields,    after_quote, c, field, i, in_quote, n) {
                delete fields
                after_quote = 0
                field = ""
                in_quote = 0
                n = 1
                for (i = 1; i <= length(line); i += 1) {
                    c = substr(line, i, 1)
                    if (in_quote) {
                        if (c == "\"") {
                            if (substr(line, i + 1, 1) == "\"") {
                                field = field "\""
                                i += 1
                            } else {
                                in_quote = 0
                                after_quote = 1
                            }
                        } else {
                            field = field c
                        }
                    } else if (after_quote) {
                        if (c != ",") {
                            return 0
                        }
                        fields[n] = field
                        n += 1
                        field = ""
                        after_quote = 0
                    } else if (c == ",") {
                        fields[n] = field
                        n += 1
                        field = ""
                    } else if (c == "\"") {
                        if (length(field) != 0) {
                            return 0
                        }
                        in_quote = 1
                    } else {
                        field = field c
                    }
                }
                if (in_quote) {
                    return 0
                }
                fields[n] = field
                return n
            }
            {
                if (substr($0, length($0), 1) != "\r") {
                    fail()
                }
                line = substr($0, 1, length($0) - 1)
                if (NR == 1) {
                    if (line != "path,sha256") {
                        fail()
                    }
                    next
                }
                count = parse_csv_record(line, fields)
                if (count != 2) {
                    fail()
                }
                printf "entry%s%s%s%s\n", separator, fields[1], separator, fields[2]
                emitted += 1
            }
            END {
                if (!failed && NR > 0) {
                    printf "complete%s%d\n", separator, emitted
                }
            }
        ' "$manifest"
    )
    ((${#rows[@]} > 0)) || exit 66
    final=${rows[-1]}
    [[ $final == complete"$separator"* ]] || exit 66
    [[ ${final#*"$separator"} =~ ^(0|[1-9][0-9]*)$ ]] || exit 66
    ((${final#*"$separator"} == ${#rows[@]} - 1)) || exit 66
    for row in "${rows[@]:0:${#rows[@]}-1}"; do
        fields=()
        IFS=$separator read -r -a fields <<< "$row"
        ((${#fields[@]} == 3)) || exit 66
        [[ ${fields[0]} == entry ]] || exit 66
        append_record "${fields[1]}" "${fields[2]}"
    done
}

parse_nul_pairs() {
    local path
    local digest
    while :; do
        path=
        if IFS= read -r -d '' path; then
            digest=
            IFS= read -r -d '' digest || exit 66
            append_record "$path" "$digest"
        else
            [[ -z $path ]] || exit 66
            break
        fi
    done < "$manifest"
}

case $manifest_layout in
    sha256sum-text) parse_sha256sum_text ;;
    jsonl) parse_jsonl ;;
    csv) parse_csv ;;
    nul-pairs) parse_nul_pairs ;;
esac
((${#paths[@]} == ${#declared_digests[@]}))

sorted_rows=()
mapfile -t sorted_rows < <(
    for ((index = 0; index < ${#paths[@]}; index += 1)); do
        printf '%s%s%s%s%d\n' \
            "${paths[index]}" "$separator" \
            "${declared_digests[index]}" "$separator" "$index"
    done |
        sort -t "$separator" -k1,1 -k2,2 --
)
((${#sorted_rows[@]} == ${#paths[@]}))

sorted_paths=()
sorted_declared=()
statuses=()
actual_digests=()

classify() {
    local path=$1
    local declared=$2
    local component
    local components=()
    local cursor=$asset_root
    local index
    local last_index
    local digest_line
    local actual

    IFS=/ read -r -a components <<< "$path"
    last_index=$((${#components[@]} - 1))
    for ((index = 0; index <= last_index; index += 1)); do
        component=${components[index]}
        cursor+=/$component
        if [[ -L $cursor ]]; then
            printf 'symlink%s\n' "$separator"
            return
        fi
        if ((index < last_index)); then
            if [[ ! -e $cursor || ! -d $cursor ]]; then
                printf 'missing%s\n' "$separator"
                return
            fi
        fi
    done

    if [[ ! -e $cursor ]]; then
        printf 'missing%s\n' "$separator"
    elif [[ -d $cursor ]]; then
        printf 'directory%s\n' "$separator"
    elif [[ ! -f $cursor ]]; then
        exit 66
    elif digest_line=$(sha256sum -- "$cursor" 2>/dev/null); then
        actual=${digest_line:0:64}
        valid_digest "$actual" || exit 66
        if [[ $actual == "$declared" ]]; then
            printf 'ok%s%s\n' "$separator" "$actual"
        else
            printf 'checksum-mismatch%s%s\n' "$separator" "$actual"
        fi
    else
        printf 'unreadable%s\n' "$separator"
    fi
}

issue_count=0
for row in "${sorted_rows[@]}"; do
    fields=()
    IFS=$separator read -r -a fields <<< "$row"
    ((${#fields[@]} == 3)) || exit 66
    path=${fields[0]}
    declared=${fields[1]}
    classification=$(classify "$path" "$declared")
    status=${classification%%"$separator"*}
    actual=${classification#*"$separator"}
    case $status in
        ok|checksum-mismatch)
            valid_digest "$actual" || exit 66
            ;;
        missing|symlink|directory|unreadable)
            [[ -z $actual ]] || exit 66
            ;;
        *)
            exit 66
            ;;
    esac
    sorted_paths+=("$path")
    sorted_declared+=("$declared")
    statuses+=("$status")
    actual_digests+=("$actual")
    if [[ $status != ok ]]; then
        ((issue_count += 1))
    fi
done

entry_count=${#sorted_paths[@]}
actions=()
action_arguments=()
action_count=0
unresolved_count=0

for ((index = 0; index < entry_count; index += 1)); do
    status=${statuses[index]}
    actual=${actual_digests[index]}
    path=${sorted_paths[index]}
    action_argument=
    case $repair_policy in
        report-only)
            action=report
            ;;
        replace-digest)
            case $status in
                ok) action=keep ;;
                checksum-mismatch)
                    action=replace-digest
                    action_argument=$actual
                    ((action_count += 1))
                    ;;
                *)
                    action=unresolved
                    ((unresolved_count += 1))
                    ;;
            esac
            ;;
        drop-missing)
            case $status in
                ok) action=keep ;;
                missing)
                    action=drop-record
                    ((action_count += 1))
                    ;;
                *)
                    action=unresolved
                    ((unresolved_count += 1))
                    ;;
            esac
            ;;
        quarantine-mismatch)
            case $status in
                ok) action=keep ;;
                checksum-mismatch)
                    action=quarantine-asset
                    action_argument=quarantine/$path
                    ((action_count += 1))
                    ;;
                *)
                    action=unresolved
                    ((unresolved_count += 1))
                    ;;
            esac
            ;;
        strict-reject)
            if ((issue_count == 0)); then
                action=keep
            else
                action=reject-batch
            fi
            ;;
    esac
    actions+=("$action")
    action_arguments+=("$action_argument")
done

if ((issue_count == 0)); then
    state=clean
else
    case $repair_policy in
        report-only) state=reported ;;
        strict-reject) state=rejected ;;
        *)
            if ((unresolved_count == 0)); then
                state=planned
            else
                state=partial
            fi
            ;;
    esac
fi

mkdir -p -- output
{
    jq -cn \
        --argjson action_count "$action_count" \
        --argjson entry_count "$entry_count" \
        --argjson issue_count "$issue_count" \
        --arg policy "$repair_policy" \
        --arg state "$state" \
        --argjson unresolved_count "$unresolved_count" \
        '{
            action_count: $action_count,
            entry_count: $entry_count,
            issue_count: $issue_count,
            policy: $policy,
            record: "plan",
            state: $state,
            unresolved_count: $unresolved_count
        }'
    for ((index = 0; index < entry_count; index += 1)); do
        jq -cn \
            --arg action "${actions[index]}" \
            --arg action_argument "${action_arguments[index]}" \
            --arg actual_sha256 "${actual_digests[index]}" \
            --arg declared_sha256 "${sorted_declared[index]}" \
            --arg path "${sorted_paths[index]}" \
            --arg status "${statuses[index]}" \
            '{
                action: $action,
                action_argument:
                    (if $action_argument == "" then null else $action_argument end),
                actual_sha256:
                    (if $actual_sha256 == "" then null else $actual_sha256 end),
                declared_sha256: $declared_sha256,
                path: $path,
                record: "entry",
                status: $status
            }'
    done
} > "$output_path"
""".lstrip()


_HAND_AUTHORED_BASH_SHA256 = (
    "e25f8114b6ac5c5d6bbec863bcf99ac4fb2313e03519775e02f3ae1390bd699f"
)


def _binary_paths(
    test: unittest.TestCase | None = None,
) -> tuple[str, dict[str, str]]:
    def unavailable(message: str) -> None:
        if test is None:
            raise RuntimeError(message)
        test.skipTest(message)

    if os.name != "posix":
        unavailable("the fixed checksum-repair Bash canary requires POSIX")
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        unavailable(
            "the fixed checksum-repair Bash canary requires its normal "
            "non-root fixture owner"
        )
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
                "values=(alpha beta); "
                "mapfile -t rows < <(printf '%s\\n' \"${values[@]}\"); "
                "[[ ${#rows[@]} == 2 && ${rows[1]} == beta ]]"
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
        unavailable("bash lacks the required array/mapfile features")

    tools: dict[str, str] = {}
    for name in repair.CHECKSUM_REPAIR_PLAN_ALLOWED_TOOLS:
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
    script = root / "fixed-checksum-repair-plan-canary.bash"
    script.write_text(_HAND_AUTHORED_BASH, encoding="utf-8", newline="\n")
    script.chmod(0o400)
    return script, tool_root


def _run_fixed_canary(
    bash: str,
    script: Path,
    tool_root: Path,
    workspace: Path,
    manifest_layout: str,
    repair_policy: str,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            bash,
            "--noprofile",
            "--norc",
            str(script),
            manifest_layout,
            repair_policy,
        ],
        cwd=workspace,
        env={
            "HOME": str(workspace),
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
    tasks = repair.build_checksum_repair_plan_tasks()
    task = next(
        item
        for item in tasks
        if item.parameters.manifest_layout == "csv"
        and item.parameters.repair_policy == "quarantine-mismatch"
    )
    profile = next(
        item
        for item in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        if item.profile_id == "partial-permissions"
    )
    bundle = repair.build_checksum_repair_plan_fixture_bundle(task, profile)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        script, tool_root = _write_fixed_canary(root, tools)
        workspace = root / "workspace"
        with repair.materialize_checksum_repair_plan_fixture(
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
                task.parameters.manifest_layout,
                task.parameters.repair_policy,
            )
            if (
                completed.returncode != 0
                or completed.stdout
                or completed.stderr
                or not repair.verify_checksum_repair_plan_workspace(
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


class ChecksumRepairPlanBashCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = repair.build_checksum_repair_plan_tasks()

    def test_fixed_literal_solves_all_twenty_cells_and_five_profiles(
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
                set(repair.CHECKSUM_REPAIR_PLAN_ALLOWED_TOOLS),
            )
            passed = 0
            for task_index, task in enumerate(self.tasks):
                self.assertIs(task.candidate_execution_authorized, False)
                self.assertIs(task.model_selection_eligible, False)
                self.assertIs(task.claim_authorized, False)
                for profile_index, profile in enumerate(
                    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
                ):
                    bundle = repair.build_checksum_repair_plan_fixture_bundle(
                        task,
                        profile,
                    )
                    workspace = (
                        root
                        / "workspaces"
                        / f"{task_index:02d}-{profile_index}"
                    )
                    with self.subTest(
                        manifest_layout=task.parameters.manifest_layout,
                        repair_policy=task.parameters.repair_policy,
                        profile=profile.profile_id,
                    ), repair.materialize_checksum_repair_plan_fixture(
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
                            task.parameters.manifest_layout,
                            task.parameters.repair_policy,
                        )
                        self.assertEqual(
                            completed.returncode,
                            0,
                            completed.stdout + completed.stderr,
                        )
                        self.assertEqual(completed.stdout, b"")
                        self.assertEqual(completed.stderr, b"")
                        self.assertTrue(
                            repair.verify_checksum_repair_plan_workspace(
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
            "from tests.test_executable_checksum_repair_plan_bash_canary "
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

    def test_literal_hash_tool_budget_and_nonclaiming_boundary(self) -> None:
        self.assertEqual(
            repair.CHECKSUM_REPAIR_PLAN_ALLOWED_TOOLS,
            ("awk", "jq", "mkdir", "sha256sum", "sort"),
        )
        self.assertEqual(
            repair.CHECKSUM_REPAIR_PLAN_MANIFEST_LAYOUTS,
            ("sha256sum-text", "jsonl", "csv", "nul-pairs"),
        )
        self.assertEqual(
            repair.CHECKSUM_REPAIR_PLAN_REPAIR_POLICIES,
            (
                "report-only",
                "replace-digest",
                "drop-missing",
                "quarantine-mismatch",
                "strict-reject",
            ),
        )
        self.assertEqual(
            repair.CHECKSUM_REPAIR_PLAN_OUTPUT,
            "output/repair-plan.jsonl",
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

        self.assertIs(repair.CHECKSUM_REPAIR_PLAN_FINAL_PLAN_OBSERVED, True)
        self.assertIs(
            repair.CHECKSUM_REPAIR_PLAN_INPUT_PRESERVATION_OBSERVED,
            True,
        )
        self.assertIs(
            repair.CHECKSUM_REPAIR_PLAN_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE,
            True,
        )
        for boundary in (
            repair.CHECKSUM_REPAIR_PLAN_REPAIR_EXECUTION_OBSERVED,
            repair.CHECKSUM_REPAIR_PLAN_QUARANTINE_EXECUTION_OBSERVED,
            repair.CHECKSUM_REPAIR_PLAN_ATOMICITY_OBSERVED,
            repair.CHECKSUM_REPAIR_PLAN_TOOL_HISTORY_OBSERVED,
            repair.CHECKSUM_REPAIR_PLAN_READ_SCOPE_OBSERVED,
            repair.CHECKSUM_REPAIR_PLAN_CANDIDATE_EXIT_STATUS_OBSERVED,
            repair.CHECKSUM_REPAIR_PLAN_DIRECTORY_PERMISSION_ERRORS_COVERED,
            repair.CHECKSUM_REPAIR_PLAN_SPECIAL_FILE_KINDS_COVERED,
            repair.CHECKSUM_REPAIR_PLAN_ANCESTOR_SYMLINKS_COVERED,
            repair.CHECKSUM_REPAIR_PLAN_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
        ):
            self.assertIs(boundary, False)

        self.assertNotIn("/usr/bin/", _HAND_AUTHORED_BASH)
        self.assertNotIn("/bin/", _HAND_AUTHORED_BASH)
        self.assertNotIn("python", _HAND_AUTHORED_BASH.lower())
        self.assertNotIn("perl", _HAND_AUTHORED_BASH.lower())
        self.assertNotIn("find ", _HAND_AUTHORED_BASH)
        self.assertNotIn("stat ", _HAND_AUTHORED_BASH)
        self.assertNotIn("cat ", _HAND_AUTHORED_BASH)
        self.assertNotIn("cp ", _HAND_AUTHORED_BASH)
        self.assertNotIn("mv ", _HAND_AUTHORED_BASH)
        self.assertNotIn("rm ", _HAND_AUTHORED_BASH)
        self.assertNotIn("chmod ", _HAND_AUTHORED_BASH)
        self.assertIn("sha256sum --", _HAND_AUTHORED_BASH)
        self.assertIn("sort -t", _HAND_AUTHORED_BASH)
        self.assertIn("jq --stream", _HAND_AUTHORED_BASH)
        self.assertIn("awk -v", _HAND_AUTHORED_BASH)
        self.assertEqual(
            sha256(_HAND_AUTHORED_BASH.encode("utf-8")).hexdigest(),
            _HAND_AUTHORED_BASH_SHA256,
        )


if __name__ == "__main__":
    unittest.main()
