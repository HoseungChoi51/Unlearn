"""Fixed reviewed Bash feasibility canary for process-lifecycle deltas.

Only the immutable Bash literal below is executed.  It is public
method-development feasibility evidence for one source-reviewed program, not
a caller-selected candidate API, production sandbox, scored evaluation,
model-selection input, or evidence about model quality.  The restricted PATH
demonstrates only that this literal stays within the family's exact external
tool budget.  Final-state verification does not prove tool or read history,
process history, filesystem atomicity, transient behavior, candidate exit
status, or global quiescence.
"""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_process_lifecycle_delta as lifecycle  # noqa: E402
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)


_HAND_AUTHORED_BASH = r"""
set -euo pipefail

export LC_ALL=C
export TZ=UTC
umask 022
unset BASH_ENV CDPATH ENV GLOBIGNORE

fail() {
    exit 70
}

if [[ $# -ne 2 ]]; then
    exit 63
fi
snapshot_pair=$1
selection_policy=$2
case $snapshot_pair in
    status-only|status-and-cmdline|status-and-cgroups|complete-synthetic-proc) ;;
    *) exit 64 ;;
esac
case $selection_policy in
    all-changes|starts-only|exits-only|state-changes|resource-threshold-crossings) ;;
    *) exit 65 ;;
esac

for required_tool in awk comm jq mkdir sort; do
    command -v "$required_tool" >/dev/null 2>&1 || fail
done

SOURCE=input/process-lifecycle
PAIR_PATH=$SOURCE/pair.json
BEFORE_ROOT=$SOURCE/before
AFTER_ROOT=$SOURCE/after
OUTPUT_ROOT=output
OUTPUT_PATH=output/transitions.jsonl

[[ -d $SOURCE && ! -L $SOURCE ]] || fail
[[ -d $BEFORE_ROOT && ! -L $BEFORE_ROOT ]] || fail
[[ -d $AFTER_ROOT && ! -L $AFTER_ROOT ]] || fail
[[ ! -e $OUTPUT_ROOT && ! -L $OUTPUT_ROOT ]] || fail

JSON_VALUE=
read_canonical_json() {
    local path=$1
    local maximum_bytes=$2
    local raw=
    local canonical
    local read_status
    JSON_VALUE=
    [[ ! -L $path && -f $path && -r $path ]] || return 1
    if IFS= read -r -d '' raw < "$path"; then
        return 1
    else
        read_status=$?
    fi
    [[ $read_status -eq 1 ]] || return 1
    [[ ${#raw} -le $maximum_bytes ]] || return 1
    canonical=$(jq -cS . -- "$path" 2>/dev/null) || return 1
    [[ $raw == "$canonical"$'\n' ]] || return 1
    JSON_VALUE=$canonical
}

read_canonical_json "$PAIR_PATH" 4096 || fail
PAIR_JSON=$JSON_VALUE
if ! jq -e '
    def integer:
        type == "number"
        and . == floor
        and (tojson | test("^(0|[1-9][0-9]*)$"));
    def positive_safe:
        integer and . >= 1 and . <= 9007199254740991;
    def endpoint:
        type == "object"
        and keys == ["boot_id", "snapshot_ticks"]
        and (.boot_id | type == "string")
        and (.boot_id | test(
            "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        ))
        and (.snapshot_ticks | positive_safe);
    type == "object"
    and keys == ["after", "before", "schema_version", "thresholds"]
    and (.schema_version | integer)
    and .schema_version == 1
    and (.before | endpoint)
    and (.after | endpoint)
    and .before.boot_id == .after.boot_id
    and .before.snapshot_ticks < .after.snapshot_ticks
    and (.thresholds | type == "object")
    and (.thresholds | keys == ["cpu_milli_percent", "rss_kib"])
    and (.thresholds.rss_kib | positive_safe)
    and (.thresholds.cpu_milli_percent | integer)
    and .thresholds.cpu_milli_percent >= 1
    and .thresholds.cpu_milli_percent <= 100000
' <<< "$PAIR_JSON" >/dev/null 2>&1; then
    fail
fi
pair_line=$(jq -r '
    [
        .before.boot_id,
        .before.snapshot_ticks,
        .after.snapshot_ticks,
        .thresholds.rss_kib,
        .thresholds.cpu_milli_percent
    ] | @tsv
' <<< "$PAIR_JSON" 2>/dev/null) || fail
IFS=$'\t' read -r \
    BOOT_ID BEFORE_TICKS AFTER_TICKS RSS_THRESHOLD CPU_THRESHOLD \
    <<< "$pair_line"

shopt -s nullglob dotglob
collect_pids() {
    local endpoint=$1
    local output_name=$2
    local -n output=$output_name
    local path
    local name
    local value
    output=()
    for path in "$endpoint"/*; do
        name=${path##*/}
        if [[ $name =~ ^[1-9][0-9]*$ ]]; then
            if [[ ${#name} -le 7 ]]; then
                value=$((10#$name))
                if (( value <= 4194304 )); then
                    output+=("$name")
                fi
            fi
        fi
    done
    (( ${#output[@]} <= 64 ))
}

BEFORE_PIDS=()
AFTER_PIDS=()
collect_pids "$BEFORE_ROOT" BEFORE_PIDS || fail
collect_pids "$AFTER_ROOT" AFTER_PIDS || fail

print_pid_keys() {
    local pid
    for pid in "$@"; do
        printf '%07d\n' "$((10#$pid))"
    done
}

UNION_PIDS=()
mapfile -t UNION_PIDS < <(
    comm \
        <(print_pid_keys "${BEFORE_PIDS[@]}" | sort -u) \
        <(print_pid_keys "${AFTER_PIDS[@]}" | sort -u) \
    | awk 'NF { print $1 + 0 }'
)
(( ${#UNION_PIDS[@]} <= 128 )) || fail

OBS_STATE=
OBS_PROJECTION=
observe_process() {
    local endpoint=$1
    local endpoint_ticks=$2
    local pid=$3
    local root=$endpoint/$pid
    local status
    local sidecar
    OBS_STATE=absent
    OBS_PROJECTION=
    if [[ ! -e $root && ! -L $root ]]; then
        return 0
    fi
    OBS_STATE=unknown
    [[ ! -L $root && -d $root && -r $root && -x $root ]] || return 0
    read_canonical_json "$root/status.json" 4096 || return 0
    status=$JSON_VALUE
    if ! jq -e \
        --argjson expected_pid "$pid" \
        --argjson endpoint_ticks "$endpoint_ticks" '
        def integer:
            type == "number"
            and . == floor
            and (tojson | test("^(0|[1-9][0-9]*)$"));
        def bounded($minimum; $maximum):
            integer and . >= $minimum and . <= $maximum;
        type == "object"
        and keys == [
            "comm",
            "cpu_milli_percent",
            "pid",
            "ppid",
            "rss_kib",
            "start_ticks",
            "state",
            "uid"
        ]
        and (.pid | bounded(1; 4194304))
        and .pid == $expected_pid
        and (.ppid | bounded(0; 4194304))
        and (.uid | bounded(0; 4294967295))
        and (.start_ticks | bounded(1; 9007199254740991))
        and .start_ticks <= $endpoint_ticks
        and (.state | type == "string")
        and (.state | test("^[RSDZTI]$"))
        and (.rss_kib | bounded(0; 9007199254740991))
        and (.cpu_milli_percent | bounded(0; 100000))
        and (.comm | type == "string")
        and (.comm | utf8bytelength >= 1 and utf8bytelength <= 64)
        and (.comm | test("[\\p{Cc}\\p{Cf}]") | not)
    ' <<< "$status" >/dev/null 2>&1; then
        return 0
    fi

    case $snapshot_pair in
        status-only)
            OBS_PROJECTION=$status
            ;;
        status-and-cmdline)
            read_canonical_json "$root/cmdline.json" 4096 || return 0
            sidecar=$JSON_VALUE
            if ! jq -e '
                . as $items
                | type == "array"
                and length <= 32
                and all(.[];
                    type == "string"
                    and utf8bytelength <= 128
                    and (contains("\u0000") | not)
                )
                and (
                    [$items[] | utf8bytelength] | (add // 0)
                ) <= 512
            ' <<< "$sidecar" >/dev/null 2>&1; then
                return 0
            fi
            OBS_PROJECTION=$(jq -cnS \
                --argjson status "$status" \
                --argjson sidecar "$sidecar" \
                '$status + {argv: $sidecar}') || return 0
            ;;
        status-and-cgroups)
            read_canonical_json "$root/cgroups.json" 4096 || return 0
            sidecar=$JSON_VALUE
            if ! jq -e '
                . as $items
                | type == "array"
                and length <= 32
                and all(.[];
                    type == "string"
                    and utf8bytelength >= 1
                    and utf8bytelength <= 128
                    and startswith("/")
                    and (test("\\u0000|\\r|\\n|\\p{Cf}") | not)
                )
                and ($items == ($items | sort))
                and ($items | length) == ($items | unique | length)
                and (
                    [$items[] | utf8bytelength] | (add // 0)
                ) <= 512
            ' <<< "$sidecar" >/dev/null 2>&1; then
                return 0
            fi
            OBS_PROJECTION=$(jq -cnS \
                --argjson status "$status" \
                --argjson sidecar "$sidecar" \
                '$status + {cgroups: $sidecar}') || return 0
            ;;
        complete-synthetic-proc)
            read_canonical_json "$root/cmdline.json" 4096 || return 0
            local argv=$JSON_VALUE
            if ! jq -e '
                . as $items
                | type == "array"
                and length <= 32
                and all(.[];
                    type == "string"
                    and utf8bytelength <= 128
                    and (contains("\u0000") | not)
                )
                and (
                    [$items[] | utf8bytelength] | (add // 0)
                ) <= 512
            ' <<< "$argv" >/dev/null 2>&1; then
                return 0
            fi
            read_canonical_json "$root/cgroups.json" 4096 || return 0
            local cgroups=$JSON_VALUE
            if ! jq -e '
                . as $items
                | type == "array"
                and length <= 32
                and all(.[];
                    type == "string"
                    and utf8bytelength >= 1
                    and utf8bytelength <= 128
                    and startswith("/")
                    and (test("\\u0000|\\r|\\n|\\p{Cf}") | not)
                )
                and ($items == ($items | sort))
                and ($items | length) == ($items | unique | length)
                and (
                    [$items[] | utf8bytelength] | (add // 0)
                ) <= 512
            ' <<< "$cgroups" >/dev/null 2>&1; then
                return 0
            fi
            OBS_PROJECTION=$(jq -cnS \
                --argjson status "$status" \
                --argjson argv "$argv" \
                --argjson cgroups "$cgroups" \
                '$status + {argv: $argv, cgroups: $cgroups}') || return 0
            ;;
    esac
    OBS_STATE=valid
}

EVENT_ROWS=()
ROW=
append_selected_row() {
    local row=$1
    local event
    event=$(jq -r '.event' <<< "$row" 2>/dev/null) || fail
    case $selection_policy in
        all-changes)
            EVENT_ROWS+=("$row")
            ;;
        starts-only)
            [[ $event == started ]] && EVENT_ROWS+=("$row")
            ;;
        exits-only)
            [[ $event == exited ]] && EVENT_ROWS+=("$row")
            ;;
        state-changes)
            if [[ $event == changed ]] && jq -e '
                .changed_fields | index("state") != null
            ' <<< "$row" >/dev/null 2>&1; then
                EVENT_ROWS+=("$row")
            fi
            ;;
        resource-threshold-crossings)
            if [[ $event == changed ]] && jq -e '
                .threshold_crossings.rss_kib != null
                or .threshold_crossings.cpu_milli_percent != null
            ' <<< "$row" >/dev/null 2>&1; then
                EVENT_ROWS+=("$row")
            fi
            ;;
    esac
    return 0
}

make_started_row() {
    local pid=$1
    local projection=$2
    local start_ticks
    start_ticks=$(jq -r '.start_ticks' <<< "$projection" 2>/dev/null) \
        || return 1
    ROW=$(jq -cnS \
        --arg boot_id "$BOOT_ID" \
        --argjson pid "$pid" \
        --argjson start_ticks "$start_ticks" \
        --argjson after "$projection" '
        {
            boot_id: $boot_id,
            pid: $pid,
            start_ticks: $start_ticks,
            event: "started",
            before: null,
            after: $after,
            changed_fields: [],
            threshold_crossings: {
                rss_kib: null,
                cpu_milli_percent: null
            }
        }
    ') || return 1
}

make_exited_row() {
    local pid=$1
    local projection=$2
    local start_ticks
    start_ticks=$(jq -r '.start_ticks' <<< "$projection" 2>/dev/null) \
        || return 1
    ROW=$(jq -cnS \
        --arg boot_id "$BOOT_ID" \
        --argjson pid "$pid" \
        --argjson start_ticks "$start_ticks" \
        --argjson before "$projection" '
        {
            boot_id: $boot_id,
            pid: $pid,
            start_ticks: $start_ticks,
            event: "exited",
            before: $before,
            after: null,
            changed_fields: [],
            threshold_crossings: {
                rss_kib: null,
                cpu_milli_percent: null
            }
        }
    ') || return 1
}

make_changed_row() {
    local pid=$1
    local before=$2
    local after=$3
    local start_ticks
    start_ticks=$(jq -r '.start_ticks' <<< "$before" 2>/dev/null) \
        || return 1
    ROW=$(jq -cnS \
        --arg boot_id "$BOOT_ID" \
        --argjson pid "$pid" \
        --argjson start_ticks "$start_ticks" \
        --argjson before "$before" \
        --argjson after "$after" \
        --argjson rss_threshold "$RSS_THRESHOLD" \
        --argjson cpu_threshold "$CPU_THRESHOLD" '
        def crossing($old; $new; $threshold):
            if $old < $threshold and $new >= $threshold then "upward"
            elif $old >= $threshold and $new < $threshold then "downward"
            else null
            end;
        [
            "ppid",
            "uid",
            "state",
            "rss_kib",
            "cpu_milli_percent",
            "comm",
            "argv",
            "cgroups"
        ]
        | map(select($before[.] != $after[.]))
        | if length == 0 then null
          else {
              boot_id: $boot_id,
              pid: $pid,
              start_ticks: $start_ticks,
              event: "changed",
              before: $before,
              after: $after,
              changed_fields: .,
              threshold_crossings: {
                  rss_kib: crossing(
                      $before.rss_kib;
                      $after.rss_kib;
                      $rss_threshold
                  ),
                  cpu_milli_percent: crossing(
                      $before.cpu_milli_percent;
                      $after.cpu_milli_percent;
                      $cpu_threshold
                  )
              }
          }
          end
    ') || return 1
}

for pid in "${UNION_PIDS[@]}"; do
    observe_process "$BEFORE_ROOT" "$BEFORE_TICKS" "$pid"
    before_state=$OBS_STATE
    before_projection=$OBS_PROJECTION
    observe_process "$AFTER_ROOT" "$AFTER_TICKS" "$pid"
    after_state=$OBS_STATE
    after_projection=$OBS_PROJECTION

    if [[ $before_state == unknown || $after_state == unknown ]]; then
        continue
    fi
    if [[ $before_state == absent && $after_state == valid ]]; then
        after_start=$(jq -r '.start_ticks' \
            <<< "$after_projection" 2>/dev/null) || fail
        if (( 10#$after_start > 10#$BEFORE_TICKS \
            && 10#$after_start <= 10#$AFTER_TICKS )); then
            make_started_row "$pid" "$after_projection" || fail
            append_selected_row "$ROW"
        fi
        continue
    fi
    if [[ $before_state == valid && $after_state == absent ]]; then
        make_exited_row "$pid" "$before_projection" || fail
        append_selected_row "$ROW"
        continue
    fi
    if [[ $before_state == valid && $after_state == valid ]]; then
        before_start=$(jq -r '.start_ticks' \
            <<< "$before_projection" 2>/dev/null) || fail
        after_start=$(jq -r '.start_ticks' \
            <<< "$after_projection" 2>/dev/null) || fail
        if [[ $before_start == "$after_start" ]]; then
            make_changed_row \
                "$pid" "$before_projection" "$after_projection" || fail
            if [[ $ROW != null ]]; then
                append_selected_row "$ROW"
            fi
        elif (( 10#$after_start > 10#$BEFORE_TICKS \
            && 10#$after_start <= 10#$AFTER_TICKS )); then
            make_exited_row "$pid" "$before_projection" || fail
            append_selected_row "$ROW"
            make_started_row "$pid" "$after_projection" || fail
            append_selected_row "$ROW"
        fi
    fi
done

total_output_bytes=0
for row in "${EVENT_ROWS[@]}"; do
    (( total_output_bytes += ${#row} + 1 ))
    (( total_output_bytes <= 1048576 )) || fail
done

mkdir -m 0755 -- "$OUTPUT_ROOT"
: > "$OUTPUT_PATH"
for row in "${EVENT_ROWS[@]}"; do
    printf '%s\n' "$row" >> "$OUTPUT_PATH"
done
""".lstrip()


_HAND_AUTHORED_BASH_SHA256 = (
    "bb1886ebf06f45c51cc534afe9c29241b2f502991703d02d1e87cc8501189638"
)
_HAND_AUTHORED_BASH_BYTE_COUNT = 15_813
_AGGREGATE_TEST_VECTOR_SHA256 = (
    "b5db3d65c4fa72e0ab1a0a743d93c1b36542fbde470b94f9f078b4ec4d48a88c"
)
_BOUNDARY_VECTOR_SHA256 = (
    "ad75dbef925bbd90f383ba5de7a3009078238b75416e94e445c163b4010efff8"
)
_FAILURE_VECTOR_SHA256 = (
    "7f4d367e4f000335bdd5dcca6a3c49749e5a86e84ba66861abc54a26b6624bbd"
)


def _binary_paths() -> tuple[str, dict[str, str]]:
    if os.name != "posix":
        raise unittest.SkipTest(
            "the fixed Bash feasibility canary requires POSIX"
        )
    bash = shutil.which("bash")
    if bash is None or not os.access(bash, os.X_OK):
        raise unittest.SkipTest("bash is unavailable")
    tools: dict[str, str] = {}
    for name in lifecycle.PROCESS_LIFECYCLE_DELTA_ALLOWED_TOOLS:
        path = shutil.which(name)
        if path is None or not os.access(path, os.X_OK):
            raise unittest.SkipTest(
                f"required canary tool {name!r} is unavailable"
            )
        tools[name] = path
    probe = subprocess.run(
        [
            tools["jq"],
            "-n",
            (
                '"x\\u00ady" '
                '| if test("[\\\\p{Cc}\\\\p{Cf}]") '
                'and (["/a","/b"] == (["/a","/b"] | sort)) '
                "then empty else error(\"missing jq semantics\") end"
            ),
        ],
        env={"LANG": "C", "LC_ALL": "C", "PATH": "", "TZ": "UTC"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=5,
    )
    if probe.returncode != 0 or probe.stdout or probe.stderr:
        raise RuntimeError(
            "jq lacks the reviewed Unicode and ordering semantics"
        )
    return bash, tools


def _write_fixed_canary(
    root: Path,
    tools: dict[str, str],
) -> tuple[Path, Path]:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    tool_root = root / "allowed-tools"
    tool_root.mkdir(mode=0o700)
    for name, target in tools.items():
        os.symlink(Path(target).resolve(), tool_root / name)
    script = root / "fixed-process-lifecycle-delta-canary.bash"
    script.write_text(_HAND_AUTHORED_BASH, encoding="utf-8", newline="\n")
    script.chmod(0o400)
    return script, tool_root


def _run_fixed_canary(
    bash: str,
    script: Path,
    tool_root: Path,
    workspace: Path,
    snapshot_pair: str,
    selection_policy: str,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            bash,
            "--noprofile",
            "--norc",
            str(script),
            snapshot_pair,
            selection_policy,
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
        timeout=30,
    )


def _commit_piece(hasher: object, value: bytes) -> None:
    if type(value) is not bytes:
        raise TypeError("aggregate commitment pieces must be exact bytes")
    hasher.update(len(value).to_bytes(8, "big"))
    hasher.update(value)


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _input_snapshot(workspace: Path) -> tuple[tuple[object, ...], ...]:
    root = workspace / "input"
    records: list[tuple[object, ...]] = []
    for path in sorted(root.rglob("*"), key=lambda item: os.fsencode(item)):
        metadata = path.lstat()
        relative = path.relative_to(workspace).as_posix()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISLNK(metadata.st_mode):
            records.append(
                (
                    relative,
                    "symlink",
                    mode,
                    os.readlink(path),
                )
            )
        elif stat.S_ISDIR(metadata.st_mode):
            records.append((relative, "directory", mode))
        elif stat.S_ISREG(metadata.st_mode):
            records.append(
                (
                    relative,
                    "regular",
                    mode,
                    metadata.st_nlink,
                    (
                        path.read_bytes()
                        if mode & 0o444
                        else None
                    ),
                )
            )
        else:
            records.append((relative, "other", mode, metadata.st_mode))
    return tuple(records)


def _run_all_materializations() -> str:
    bash, tools = _binary_paths()
    tasks = lifecycle.build_process_lifecycle_delta_tasks()
    if len(tasks) != 20 or len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES) != 5:
        raise RuntimeError("reviewed canary grid is not exactly 20 by 5")
    aggregate = sha256(
        b"cbds.fixed-process-lifecycle-delta-canary.v1\0"
    )
    passed = 0
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        script, tool_root = _write_fixed_canary(root, tools)
        if {item.name for item in tool_root.iterdir()} != set(
            lifecycle.PROCESS_LIFECYCLE_DELTA_ALLOWED_TOOLS
        ):
            raise RuntimeError(
                "restricted PATH does not exactly match tool budget"
            )
        for task_index, task in enumerate(tasks):
            if (
                task.candidate_execution_authorized is not False
                or task.model_selection_eligible is not False
                or task.claim_authorized is not False
            ):
                raise RuntimeError("task unexpectedly grants research authority")
            for profile_index, profile in enumerate(
                PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
            ):
                bundle = (
                    lifecycle.build_process_lifecycle_delta_fixture_bundle(
                        task,
                        profile,
                    )
                )
                workspace = (
                    root
                    / "workspaces"
                    / f"{task_index:02d}-{profile_index}"
                )
                with lifecycle.materialize_process_lifecycle_delta_fixture(
                    task,
                    profile,
                    bundle,
                    workspace,
                ) as handle:
                    initial_input_scan = handle.scan_inputs()
                    handle.validate_input_object_identities(initial_input_scan)
                    completed = _run_fixed_canary(
                        bash,
                        script,
                        tool_root,
                        workspace,
                        task.parameters.snapshot_pair,
                        task.parameters.selection_policy,
                    )
                    if (
                        completed.returncode != 0
                        or completed.stdout
                        or completed.stderr
                    ):
                        raise RuntimeError(
                            "reviewed Bash literal failed for "
                            f"{task.parameters.to_record()!r}/"
                            f"{profile.profile_id}: "
                            + (completed.stdout + completed.stderr).decode(
                                "utf-8", errors="replace"
                            )
                        )
                    if not lifecycle.verify_process_lifecycle_delta_workspace(
                        task,
                        profile,
                        bundle,
                        handle,
                    ):
                        raise RuntimeError(
                            "reviewed Bash literal failed trusted verification "
                            f"for {task.parameters.to_record()!r}/"
                            f"{profile.profile_id}"
                        )
                    output_scan = handle.scan_outputs()
                    observed = handle.read_output_bytes(
                        output_scan,
                        lifecycle.PROCESS_LIFECYCLE_DELTA_OUTPUT,
                    )
                    if observed != bundle.oracle.state.content:
                        raise RuntimeError(
                            "reviewed Bash literal is not byte-canonical"
                        )
                    final_input_scan = handle.scan_inputs()
                    handle.validate_input_object_identities(final_input_scan)
                    if final_input_scan != initial_input_scan:
                        raise RuntimeError(
                            "reviewed Bash literal changed authenticated input"
                        )
                    for piece in (
                        task.task_id.encode("ascii"),
                        profile.profile_id.encode("ascii"),
                        bundle.definition.fixture_id.encode("ascii"),
                        bundle.definition.fixture_sha256.encode("ascii"),
                        bundle.fixture_definition_sha256.encode("ascii"),
                        bundle.descriptor.fixture_sha256.encode("ascii"),
                        observed,
                    ):
                        _commit_piece(aggregate, piece)
                    if (
                        bundle.candidate_execution_authorized is not False
                        or bundle.model_selection_eligible is not False
                        or bundle.claim_authorized is not False
                    ):
                        raise RuntimeError(
                            "fixture unexpectedly grants research authority"
                        )
                    passed += 1
    if passed != 100:
        raise RuntimeError("reviewed Bash literal did not cover 100 bundles")
    return aggregate.hexdigest()


_BOOT_ID = "01234567-89ab-cdef-0123-456789abcdef"


def _pair_value(
    *,
    before_ticks: int = 1_000,
    after_ticks: int = 2_000,
    rss_threshold: int = 4_096,
    cpu_threshold: int = 50_000,
    before_boot_id: str = _BOOT_ID,
    after_boot_id: str = _BOOT_ID,
) -> dict[str, object]:
    return {
        "after": {
            "boot_id": after_boot_id,
            "snapshot_ticks": after_ticks,
        },
        "before": {
            "boot_id": before_boot_id,
            "snapshot_ticks": before_ticks,
        },
        "schema_version": 1,
        "thresholds": {
            "cpu_milli_percent": cpu_threshold,
            "rss_kib": rss_threshold,
        },
    }


def _status_value(
    pid: int,
    start_ticks: int,
    *,
    comm: str = "manual process",
    ppid: int = 1,
    uid: int = 1_000,
    state: str = "S",
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


def _materialize_manual_base(
    workspace: Path,
    pair_payload: bytes | None = None,
) -> None:
    source = workspace / lifecycle.PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT
    (source / "before").mkdir(parents=True, mode=0o755)
    (source / "after").mkdir(mode=0o755)
    pair = source / "pair.json"
    pair.write_bytes(
        _canonical(_pair_value())
        if pair_payload is None
        else pair_payload
    )
    pair.chmod(0o600)


def _write_manual_process(
    workspace: Path,
    side: str,
    pid_name: str,
    status_value: dict[str, object],
    *,
    argv: list[str] | None = None,
    cgroups: list[str] | None = None,
    status_payload: bytes | None = None,
    status_mode: int = 0o600,
    argv_mode: int = 0o600,
    cgroups_mode: int = 0o600,
) -> None:
    root = (
        workspace
        / lifecycle.PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT
        / side
        / pid_name
    )
    root.mkdir(parents=True, mode=0o755)
    status_path = root / "status.json"
    status_path.write_bytes(
        _canonical(status_value)
        if status_payload is None
        else status_payload
    )
    status_path.chmod(status_mode)
    if argv is not None:
        argv_path = root / "cmdline.json"
        argv_path.write_bytes(_canonical(argv))
        argv_path.chmod(argv_mode)
    if cgroups is not None:
        cgroups_path = root / "cgroups.json"
        cgroups_path.write_bytes(_canonical(cgroups))
        cgroups_path.chmod(cgroups_mode)


def _started_event(
    projection: dict[str, object],
    *,
    boot_id: str = _BOOT_ID,
) -> dict[str, object]:
    return {
        "after": projection,
        "before": None,
        "boot_id": boot_id,
        "changed_fields": [],
        "event": "started",
        "pid": projection["pid"],
        "start_ticks": projection["start_ticks"],
        "threshold_crossings": {
            "cpu_milli_percent": None,
            "rss_kib": None,
        },
    }


def _exited_event(
    projection: dict[str, object],
    *,
    boot_id: str = _BOOT_ID,
) -> dict[str, object]:
    return {
        "after": None,
        "before": projection,
        "boot_id": boot_id,
        "changed_fields": [],
        "event": "exited",
        "pid": projection["pid"],
        "start_ticks": projection["start_ticks"],
        "threshold_crossings": {
            "cpu_milli_percent": None,
            "rss_kib": None,
        },
    }


def _require_manual_output(workspace: Path, expected: bytes) -> None:
    output_root = workspace / "output"
    output_path = workspace / lifecycle.PROCESS_LIFECYCLE_DELTA_OUTPUT
    root_metadata = output_root.lstat()
    output_metadata = output_path.lstat()
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_IMODE(root_metadata.st_mode) != 0o755
        or not stat.S_ISREG(output_metadata.st_mode)
        or stat.S_IMODE(output_metadata.st_mode) != 0o644
        or output_metadata.st_nlink != 1
        or output_path.read_bytes() != expected
        or {item.name for item in output_root.iterdir()}
        != {"transitions.jsonl"}
    ):
        raise RuntimeError("manual lifecycle output differs from policy")


def _boundary_material() -> tuple[
    dict[str, object],
    dict[str, object],
    list[str],
    list[str],
    bytes,
    tuple[list[str], ...],
    tuple[list[str], ...],
]:
    maximum = lifecycle.PROCESS_LIFECYCLE_DELTA_MAXIMUM_INTEGER
    pair = _pair_value(
        before_ticks=maximum - 2,
        after_ticks=maximum,
        rss_threshold=maximum,
        cpu_threshold=100_000,
    )
    status = _status_value(
        lifecycle.PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
        maximum - 1,
        comm="m" * lifecycle.PROCESS_LIFECYCLE_DELTA_COMM_MAXIMUM_UTF8_BYTES,
        ppid=lifecycle.PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID,
        uid=lifecycle.PROCESS_LIFECYCLE_DELTA_MAXIMUM_UID,
        state="I",
        rss_kib=maximum,
        cpu_milli_percent=100_000,
    )
    argv = [
        f"arg-{index:02d}-" + "x" * 9
        for index in range(lifecycle.PROCESS_LIFECYCLE_DELTA_MAXIMUM_ARRAY_ITEMS)
    ]
    cgroups = [
        f"/group-{index:02d}-" + "y" * 6
        for index in range(lifecycle.PROCESS_LIFECYCLE_DELTA_MAXIMUM_ARRAY_ITEMS)
    ]
    projection = {**status, "argv": argv, "cgroups": cgroups}
    expected = _canonical(_started_event(projection))
    bad_argv = (
        ["x" * 129],
        ["x"] * 33,
        ["a" * 103, "b" * 103, "c" * 103, "d" * 103, "e" * 101],
    )
    bad_cgroups = (
        ["/" + "x" * 128],
        [f"/g/{index:02d}" for index in range(33)],
        ["/b", "/a"],
    )
    return pair, status, argv, cgroups, expected, bad_argv, bad_cgroups


def _compute_boundary_vector_sha256() -> str:
    pair, status, argv, cgroups, expected, bad_argv, bad_cgroups = (
        _boundary_material()
    )
    vector = sha256(b"cbds.process-lifecycle-boundary-vector.v1\0")
    for piece in (
        _canonical(pair),
        _canonical(status),
        _canonical(argv),
        _canonical(cgroups),
        expected,
        *( _canonical(value) for value in bad_argv ),
        *( _canonical(value) for value in bad_cgroups ),
        b"canonical-process-count:64",
        b"canonical-process-count:65",
        b"maximum-pid:4194304",
        b"ignored-out-of-range-pid:4194305",
        b"maximum-safe-integer:9007199254740991",
        b"unsafe-integer:9007199254740992",
        b"output-maximum-bytes:1048576",
    ):
        _commit_piece(vector, piece)
    return vector.hexdigest()


def _failure_pair_payloads() -> tuple[tuple[str, bytes], ...]:
    canonical_pair = _canonical(_pair_value())
    duplicate = canonical_pair.replace(
        b'{"after":',
        b'{"schema_version":1,"after":',
        1,
    )
    whitespace = canonical_pair.replace(b'{"after":', b'{ "after":', 1)
    different_boot = _canonical(
        _pair_value(
            after_boot_id="fedcba98-7654-3210-fedc-ba9876543210"
        )
    )
    boolean_tick = canonical_pair.replace(
        b'"snapshot_ticks":1000',
        b'"snapshot_ticks":true',
        1,
    )
    exponent_tick = canonical_pair.replace(
        b'"snapshot_ticks":1000',
        b'"snapshot_ticks":1e3',
        1,
    )
    fractional_schema_version = canonical_pair.replace(
        b'"schema_version":1',
        b'"schema_version":1.0',
        1,
    )
    return (
        ("missing-final-lf", canonical_pair[:-1]),
        ("duplicate-pair-member", duplicate),
        ("noncanonical-whitespace", whitespace),
        ("different-boot-id", different_boot),
        ("boolean-snapshot-tick", boolean_tick),
        ("exponent-snapshot-tick", exponent_tick),
        ("fractional-schema-version", fractional_schema_version),
        ("invalid-utf8", canonical_pair[:-1] + b"\xff\n"),
        (
            "pair-over-byte-bound",
            b" " * (lifecycle.PROCESS_LIFECYCLE_DELTA_PAIR_MAXIMUM_BYTES + 1),
        ),
    )


def _compute_failure_vector_sha256() -> str:
    vector = sha256(b"cbds.process-lifecycle-failure-vector.v1\0")
    for name, payload in _failure_pair_payloads():
        _commit_piece(vector, name.encode("ascii"))
        _commit_piece(vector, payload)
    for marker in (
        b"pair-symlink",
        b"source-symlink",
        b"preexisting-output",
        b"required-sidecar-symlink-is-unknown",
        b"missing-required-sidecar-is-unknown",
        b"negative-zero-status-is-unknown",
        b"tool-removal:awk",
        b"tool-removal:comm",
        b"tool-removal:jq",
        b"tool-removal:mkdir",
        b"tool-removal:sort",
    ):
        _commit_piece(vector, marker)
    return vector.hexdigest()


class ProcessLifecycleDeltaBashCanaryTests(unittest.TestCase):
    def test_fixed_literal_solves_all_twenty_cells_and_five_profiles(
        self,
    ) -> None:
        self.assertEqual(
            _run_all_materializations(),
            _AGGREGATE_TEST_VECTOR_SHA256,
        )

    def test_exact_scalar_sidecar_process_and_output_bounds(self) -> None:
        self.assertEqual(
            _compute_boundary_vector_sha256(),
            _BOUNDARY_VECTOR_SHA256,
        )
        self.assertEqual(
            lifecycle.PROCESS_LIFECYCLE_DELTA_OUTPUT_MAXIMUM_BYTES,
            1024 * 1024,
        )
        self.assertEqual(
            lifecycle.PROCESS_LIFECYCLE_DELTA_SIDECAR_MAXIMUM_BYTES,
            4 * 1024,
        )
        self.assertEqual(
            lifecycle.PROCESS_LIFECYCLE_DELTA_SIDECAR_ITEM_MAXIMUM_UTF8_BYTES,
            128,
        )
        self.assertEqual(
            lifecycle.PROCESS_LIFECYCLE_DELTA_SIDECAR_TOTAL_MAXIMUM_UTF8_BYTES,
            512,
        )
        self.assertEqual(
            lifecycle.compute_process_lifecycle_delta_proved_output_bound(),
            1024 * 1024,
        )

        pair, status, argv, cgroups, expected, bad_argv, bad_cgroups = (
            _boundary_material()
        )
        bash, tools = _binary_paths()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, tool_root = _write_fixed_canary(root, tools)

            maximum_workspace = root / "maximum-valid"
            _materialize_manual_base(maximum_workspace, _canonical(pair))
            _write_manual_process(
                maximum_workspace,
                "after",
                str(lifecycle.PROCESS_LIFECYCLE_DELTA_MAXIMUM_PID),
                status,
                argv=argv,
                cgroups=cgroups,
            )
            maximum_before = _input_snapshot(maximum_workspace)
            maximum_run = _run_fixed_canary(
                bash,
                script,
                tool_root,
                maximum_workspace,
                "complete-synthetic-proc",
                "all-changes",
            )
            self.assertEqual(
                maximum_run.returncode,
                0,
                maximum_run.stdout + maximum_run.stderr,
            )
            self.assertEqual(maximum_run.stdout, b"")
            self.assertEqual(maximum_run.stderr, b"")
            _require_manual_output(maximum_workspace, expected)
            self.assertEqual(
                _input_snapshot(maximum_workspace),
                maximum_before,
            )

            for category, collections in (
                ("argv", bad_argv),
                ("cgroups", bad_cgroups),
            ):
                for index, invalid in enumerate(collections):
                    workspace = root / f"invalid-{category}-{index}"
                    _materialize_manual_base(workspace)
                    kwargs: dict[str, list[str]] = {
                        "argv": ["valid"],
                        "cgroups": ["/valid"],
                    }
                    kwargs[category] = invalid
                    _write_manual_process(
                        workspace,
                        "after",
                        "2",
                        _status_value(2, 1_500),
                        **kwargs,
                    )
                    before = _input_snapshot(workspace)
                    completed = _run_fixed_canary(
                        bash,
                        script,
                        tool_root,
                        workspace,
                        "complete-synthetic-proc",
                        "starts-only",
                    )
                    self.assertEqual(
                        completed.returncode,
                        0,
                        (category, index, completed.stdout + completed.stderr),
                    )
                    self.assertEqual(completed.stdout, b"")
                    self.assertEqual(completed.stderr, b"")
                    _require_manual_output(workspace, b"")
                    self.assertEqual(_input_snapshot(workspace), before)

            sixty_four = root / "sixty-four"
            _materialize_manual_base(sixty_four)
            expected_exits = bytearray()
            for pid in range(1, 65):
                projection = _status_value(pid, pid)
                _write_manual_process(
                    sixty_four,
                    "before",
                    str(pid),
                    projection,
                )
                expected_exits.extend(_canonical(_exited_event(projection)))
            sixty_four_run = _run_fixed_canary(
                bash,
                script,
                tool_root,
                sixty_four,
                "status-only",
                "exits-only",
            )
            self.assertEqual(
                sixty_four_run.returncode,
                0,
                sixty_four_run.stdout + sixty_four_run.stderr,
            )
            _require_manual_output(sixty_four, bytes(expected_exits))

            sixty_five = root / "sixty-five"
            _materialize_manual_base(sixty_five)
            for pid in range(1, 66):
                _write_manual_process(
                    sixty_five,
                    "before",
                    str(pid),
                    _status_value(pid, pid),
                )
            sixty_five_before = _input_snapshot(sixty_five)
            sixty_five_run = _run_fixed_canary(
                bash,
                script,
                tool_root,
                sixty_five,
                "status-only",
                "all-changes",
            )
            self.assertNotEqual(sixty_five_run.returncode, 0)
            self.assertEqual(sixty_five_run.stdout, b"")
            self.assertEqual(sixty_five_run.stderr, b"")
            self.assertFalse((sixty_five / "output").exists())
            self.assertEqual(_input_snapshot(sixty_five), sixty_five_before)

            unsafe_pair = root / "unsafe-pair"
            _materialize_manual_base(
                unsafe_pair,
                _canonical(
                    _pair_value(
                        before_ticks=9_007_199_254_740_991,
                        after_ticks=9_007_199_254_740_992,
                    )
                ),
            )
            unsafe_run = _run_fixed_canary(
                bash,
                script,
                tool_root,
                unsafe_pair,
                "status-only",
                "all-changes",
            )
            self.assertNotEqual(unsafe_run.returncode, 0)
            self.assertFalse((unsafe_pair / "output").exists())

            ignored_pid = root / "ignored-pid"
            _materialize_manual_base(ignored_pid)
            _write_manual_process(
                ignored_pid,
                "after",
                "4194305",
                _status_value(4_194_305, 1_500),
            )
            ignored_run = _run_fixed_canary(
                bash,
                script,
                tool_root,
                ignored_pid,
                "status-only",
                "all-changes",
            )
            self.assertEqual(
                ignored_run.returncode,
                0,
                ignored_run.stdout + ignored_run.stderr,
            )
            _require_manual_output(ignored_pid, b"")

    def test_malformed_partial_and_symlink_inputs_fail_closed(self) -> None:
        self.assertEqual(
            _compute_failure_vector_sha256(),
            _FAILURE_VECTOR_SHA256,
        )
        bash, tools = _binary_paths()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, tool_root = _write_fixed_canary(root, tools)
            for index, (name, payload) in enumerate(
                _failure_pair_payloads()
            ):
                workspace = root / f"failure-{index:02d}-{name}"
                _materialize_manual_base(workspace, payload)
                before = _input_snapshot(workspace)
                completed = _run_fixed_canary(
                    bash,
                    script,
                    tool_root,
                    workspace,
                    "status-only",
                    "all-changes",
                )
                self.assertNotEqual(completed.returncode, 0, name)
                self.assertEqual(completed.stdout, b"", name)
                self.assertEqual(completed.stderr, b"", name)
                self.assertFalse((workspace / "output").exists(), name)
                self.assertEqual(_input_snapshot(workspace), before, name)

            pair_symlink = root / "pair-symlink"
            _materialize_manual_base(pair_symlink)
            pair_path = pair_symlink / lifecycle.PROCESS_LIFECYCLE_DELTA_PAIR_INPUT
            pair_target = pair_symlink / "pair-target.json"
            pair_target.write_bytes(pair_path.read_bytes())
            pair_path.unlink()
            pair_path.symlink_to(pair_target)
            before = _input_snapshot(pair_symlink)
            pair_run = _run_fixed_canary(
                bash,
                script,
                tool_root,
                pair_symlink,
                "status-only",
                "all-changes",
            )
            self.assertNotEqual(pair_run.returncode, 0)
            self.assertFalse((pair_symlink / "output").exists())
            self.assertEqual(_input_snapshot(pair_symlink), before)

            preexisting = root / "preexisting-output"
            _materialize_manual_base(preexisting)
            (preexisting / "output").mkdir()
            marker = preexisting / "output" / "marker"
            marker.write_bytes(b"preserve\n")
            preexisting_run = _run_fixed_canary(
                bash,
                script,
                tool_root,
                preexisting,
                "status-only",
                "all-changes",
            )
            self.assertNotEqual(preexisting_run.returncode, 0)
            self.assertEqual(marker.read_bytes(), b"preserve\n")

            sidecar_symlink = root / "sidecar-symlink"
            _materialize_manual_base(sidecar_symlink)
            _write_manual_process(
                sidecar_symlink,
                "after",
                "2",
                _status_value(2, 1_500),
                argv=["target"],
            )
            process_root = (
                sidecar_symlink
                / lifecycle.PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT
                / "after"
                / "2"
            )
            argv_path = process_root / "cmdline.json"
            target = process_root / "cmdline-target.json"
            argv_path.replace(target)
            argv_path.symlink_to("cmdline-target.json")
            sidecar_run = _run_fixed_canary(
                bash,
                script,
                tool_root,
                sidecar_symlink,
                "status-and-cmdline",
                "starts-only",
            )
            self.assertEqual(
                sidecar_run.returncode,
                0,
                sidecar_run.stdout + sidecar_run.stderr,
            )
            _require_manual_output(sidecar_symlink, b"")

            negative_zero_status = root / "negative-zero-status"
            _materialize_manual_base(negative_zero_status)
            _write_manual_process(
                negative_zero_status,
                "after",
                "2",
                _status_value(2, 1_500, ppid=0),
            )
            status_path = (
                negative_zero_status
                / lifecycle.PROCESS_LIFECYCLE_DELTA_SOURCE_ROOT
                / "after"
                / "2"
                / "status.json"
            )
            canonical_status = status_path.read_bytes()
            negative_zero_payload = canonical_status.replace(
                b'"ppid":0',
                b'"ppid":-0',
                1,
            )
            self.assertNotEqual(negative_zero_payload, canonical_status)
            status_path.write_bytes(negative_zero_payload)
            negative_zero_run = _run_fixed_canary(
                bash,
                script,
                tool_root,
                negative_zero_status,
                "status-only",
                "starts-only",
            )
            self.assertEqual(
                negative_zero_run.returncode,
                0,
                negative_zero_run.stdout + negative_zero_run.stderr,
            )
            _require_manual_output(negative_zero_status, b"")

    def test_removing_each_declared_tool_fails_before_publication(self) -> None:
        bash, tools = _binary_paths()
        tasks = lifecycle.build_process_lifecycle_delta_tasks()
        task = tasks[0]
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        bundle = lifecycle.build_process_lifecycle_delta_fixture_bundle(
            task, profile
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, complete_tool_root = _write_fixed_canary(
                root / "complete", tools
            )
            self.assertEqual(
                {item.name for item in complete_tool_root.iterdir()},
                set(lifecycle.PROCESS_LIFECYCLE_DELTA_ALLOWED_TOOLS),
            )
            for tool_name in lifecycle.PROCESS_LIFECYCLE_DELTA_ALLOWED_TOOLS:
                case_root = root / f"missing-{tool_name}"
                case_script, tool_root = _write_fixed_canary(case_root, tools)
                (tool_root / tool_name).unlink()
                workspace = case_root / "workspace"
                with lifecycle.materialize_process_lifecycle_delta_fixture(
                    task,
                    profile,
                    bundle,
                    workspace,
                ) as handle:
                    initial = handle.scan_inputs()
                    completed = _run_fixed_canary(
                        bash,
                        case_script,
                        tool_root,
                        workspace,
                        task.parameters.snapshot_pair,
                        task.parameters.selection_policy,
                    )
                    self.assertNotEqual(
                        completed.returncode, 0, tool_name
                    )
                    self.assertEqual(completed.stdout, b"", tool_name)
                    self.assertEqual(completed.stderr, b"", tool_name)
                    self.assertFalse(
                        (workspace / "output").exists(), tool_name
                    )
                    self.assertEqual(handle.scan_inputs(), initial)

    def test_argument_domain_is_exact_quiet_and_noninteracting(self) -> None:
        bash, tools = _binary_paths()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, tool_root = _write_fixed_canary(root, tools)
            cases = (
                (),
                ("status-only",),
                ("unknown", "all-changes"),
                ("status-only", "unknown"),
                ("status-only", "all-changes", "extra"),
            )
            for index, arguments in enumerate(cases):
                workspace = root / f"arguments-{index}"
                _materialize_manual_base(workspace)
                completed = subprocess.run(
                    [
                        bash,
                        "--noprofile",
                        "--norc",
                        str(script),
                        *arguments,
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
                    timeout=30,
                )
                self.assertNotEqual(completed.returncode, 0, arguments)
                self.assertEqual(completed.stdout, b"", arguments)
                self.assertEqual(completed.stderr, b"", arguments)
                self.assertFalse((workspace / "output").exists(), arguments)

        forbidden_tokens = (
            "/proc/",
            "/sys/",
            "pgrep",
            "systemctl",
            "container",
            "renice",
            "strace",
            "sleep ",
            "kill ",
            "wait ",
        )
        for token in forbidden_tokens:
            self.assertNotIn(token, _HAND_AUTHORED_BASH)

    def test_literal_hash_tool_budget_and_nonclaim_boundary(self) -> None:
        literal = _HAND_AUTHORED_BASH.encode("utf-8")
        self.assertEqual(len(literal), _HAND_AUTHORED_BASH_BYTE_COUNT)
        self.assertEqual(
            sha256(literal).hexdigest(),
            _HAND_AUTHORED_BASH_SHA256,
        )
        self.assertRegex(
            _AGGREGATE_TEST_VECTOR_SHA256, r"\A[0-9a-f]{64}\Z"
        )
        self.assertRegex(_BOUNDARY_VECTOR_SHA256, r"\A[0-9a-f]{64}\Z")
        self.assertRegex(_FAILURE_VECTOR_SHA256, r"\A[0-9a-f]{64}\Z")
        self.assertEqual(
            lifecycle.PROCESS_LIFECYCLE_DELTA_ALLOWED_TOOLS,
            ("awk", "comm", "jq", "mkdir", "sort"),
        )
        self.assertEqual(
            lifecycle.PROCESS_LIFECYCLE_DELTA_SNAPSHOT_PAIRS,
            (
                "status-only",
                "status-and-cmdline",
                "status-and-cgroups",
                "complete-synthetic-proc",
            ),
        )
        self.assertEqual(
            lifecycle.PROCESS_LIFECYCLE_DELTA_SELECTION_POLICIES,
            (
                "all-changes",
                "starts-only",
                "exits-only",
                "state-changes",
                "resource-threshold-crossings",
            ),
        )
        self.assertTrue(
            lifecycle.PROCESS_LIFECYCLE_DELTA_FINAL_OUTPUT_OBSERVED
        )
        self.assertTrue(
            lifecycle.PROCESS_LIFECYCLE_DELTA_INPUT_PRESERVATION_OBSERVED
        )
        for value in (
            lifecycle.PROCESS_LIFECYCLE_DELTA_ATOMICITY_OBSERVED,
            lifecycle.PROCESS_LIFECYCLE_DELTA_TOOL_HISTORY_OBSERVED,
            lifecycle.PROCESS_LIFECYCLE_DELTA_READ_SCOPE_OBSERVED,
            lifecycle.PROCESS_LIFECYCLE_DELTA_CANDIDATE_EXIT_STATUS_OBSERVED,
            lifecycle.PROCESS_LIFECYCLE_DELTA_TRANSIENT_STATE_OBSERVED,
            lifecycle.PROCESS_LIFECYCLE_DELTA_LIVE_PROC_OBSERVED,
            lifecycle.PROCESS_LIFECYCLE_DELTA_PROCESS_ACTIONS_OBSERVED,
            lifecycle.PROCESS_LIFECYCLE_DELTA_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
        ):
            self.assertIs(value, False)
        self.assertTrue(
            lifecycle.PROCESS_LIFECYCLE_DELTA_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE
        )
        tasks = lifecycle.build_process_lifecycle_delta_tasks()
        for task in tasks:
            self.assertIs(task.candidate_execution_authorized, False)
            self.assertIs(task.model_selection_eligible, False)
            self.assertIs(task.claim_authorized, False)


if __name__ == "__main__":
    unittest.main()
