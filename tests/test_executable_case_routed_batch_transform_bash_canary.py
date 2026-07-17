"""Fixed hand-authored Bash feasibility canary for case-routed transforms.

This test deliberately executes one source-reviewed program constant.  It is
not a caller-selected candidate API, a production sandbox, scored evaluation,
or evidence that arbitrary synthesized Bash is safe to execute.  The fixture,
task, and bundle authority flags remain false.  A restricted PATH is a useful
feasibility check for this fixed program; it does not make final-state
verification an observer of tool, read, route, transform, or publication
history.
"""

from __future__ import annotations

from hashlib import sha256
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

import cbds.executable_case_routed_batch_transform as routed  # noqa: E402
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)


_HAND_AUTHORED_BASH = r"""
set -euo pipefail

export LC_ALL=C
umask 022

route_key=${1:?route key required}
fallback_policy=${2:?fallback policy required}
case $route_key in
    suffix|record-kind|leading-byte|declared-action) ;;
    *) exit 64 ;;
esac
case $fallback_policy in
    skip|copy-verbatim|reject-batch|route-default|emit-error-record) ;;
    *) exit 65 ;;
esac

manifest=input/batch/manifest.tsv

classify_leading_byte() {
    local payload=$1
    if [[ ! -s $payload ]]; then
        printf '%s\n' unmatched
    elif sed -n '1{/^U/q 0;q 1}' -- "$payload"; then
        printf '%s\n' upper
    elif sed -n '1{/^L/q 0;q 1}' -- "$payload"; then
        printf '%s\n' lower
    elif sed -n '1{/^T/q 0;q 1}' -- "$payload"; then
        printf '%s\n' detab
    elif sed -n '1{/^C/q 0;q 1}' -- "$payload"; then
        printf '%s\n' strip-cr
    else
        printf '%s\n' unmatched
    fi
}

classify_route() {
    local source=$1
    local kind=$2
    local action=$3
    local basename
    case $route_key in
        suffix)
            basename=${source##*/}
            case $basename in
                *.upper) printf '%s\n' upper ;;
                *.lower) printf '%s\n' lower ;;
                *.tabs) printf '%s\n' detab ;;
                *.crlf) printf '%s\n' strip-cr ;;
                *) printf '%s\n' unmatched ;;
            esac
            ;;
        record-kind)
            case $kind in
                uppercase-text) printf '%s\n' upper ;;
                lowercase-text) printf '%s\n' lower ;;
                tabbed-text) printf '%s\n' detab ;;
                crlf-text) printf '%s\n' strip-cr ;;
                *) printf '%s\n' unmatched ;;
            esac
            ;;
        leading-byte) classify_leading_byte "$source" ;;
        declared-action)
            case $action in
                uppercase) printf '%s\n' upper ;;
                lowercase) printf '%s\n' lower ;;
                expand-tabs) printf '%s\n' detab ;;
                delete-cr) printf '%s\n' strip-cr ;;
                *) printf '%s\n' unmatched ;;
            esac
            ;;
    esac
}

write_payload() {
    local source=$1
    local identifier=$2
    local route=$3
    local destination=output/routes/$route/$identifier.out
    mkdir -p -- "${destination%/*}"
    case $route in
        upper) tr 'a-z' 'A-Z' < "$source" > "$destination" ;;
        lower) tr 'A-Z' 'a-z' < "$source" > "$destination" ;;
        detab) sed $'s/\t/    /g' -- "$source" > "$destination" ;;
        strip-cr) tr -d '\r' < "$source" > "$destination" ;;
        verbatim) tr '\000' '\000' < "$source" > "$destination" ;;
        default) tr 'A-Za-z' 'N-ZA-Mn-za-m' < "$source" > "$destination" ;;
        *) exit 66 ;;
    esac
}

logical_count=0
matched_count=0
unmatched_count=0
while IFS=$'\t' read -r identifier source kind action extra; do
    [[ -n $identifier && -n $source && -n $kind && -n $action ]]
    [[ -z ${extra:-} ]]
    route=$(classify_route "$source" "$kind" "$action")
    ((logical_count += 1))
    if [[ $route == unmatched ]]; then
        ((unmatched_count += 1))
    else
        ((matched_count += 1))
    fi
done < <(sort -u -- "$manifest")

state=complete
payload_count=$matched_count
error_count=0
if [[ $fallback_policy == reject-batch && $unmatched_count -gt 0 ]]; then
    state=rejected
    payload_count=0
    error_count=$unmatched_count
elif [[ $fallback_policy == copy-verbatim || $fallback_policy == route-default ]]; then
    payload_count=$logical_count
elif [[ $fallback_policy == emit-error-record ]]; then
    error_count=$unmatched_count
fi

mkdir -p -- output
: > output/errors.tsv

if [[ $state == rejected ]]; then
    while IFS=$'\t' read -r identifier source kind action extra; do
        route=$(classify_route "$source" "$kind" "$action")
        if [[ $route == unmatched ]]; then
            printf 'rejected\t%s\t%s\n' "$identifier" "$route_key"
        fi
    done < <(sort -u -- "$manifest") > output/errors.tsv
else
    while IFS=$'\t' read -r identifier source kind action extra; do
        route=$(classify_route "$source" "$kind" "$action")
        if [[ $route != unmatched ]]; then
            write_payload "$source" "$identifier" "$route"
            continue
        fi
        case $fallback_policy in
            skip) ;;
            copy-verbatim) write_payload "$source" "$identifier" verbatim ;;
            route-default) write_payload "$source" "$identifier" default ;;
            emit-error-record)
                printf 'unmatched\t%s\t%s\n' "$identifier" "$route_key" \
                    >> output/errors.tsv
                ;;
            reject-batch) exit 67 ;;
        esac
    done < <(sort -u -- "$manifest")
fi

printf 'batch\t%s\t%d\t%d\t%d\t%d\t%d\n' \
    "$state" "$logical_count" "$matched_count" "$unmatched_count" \
    "$payload_count" "$error_count" > output/status.tsv
""".lstrip()


def _binary_paths(test: unittest.TestCase) -> tuple[str, dict[str, str]]:
    if os.name != "posix":
        test.skipTest("the fixed Bash feasibility canary requires POSIX")
    bash = shutil.which("bash")
    if bash is None:
        test.skipTest("bash is unavailable")
    tools: dict[str, str] = {}
    for name in routed.CASE_ROUTED_BATCH_TRANSFORM_ALLOWED_TOOLS:
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
    script = root / "fixed-case-routed-canary.bash"
    script.write_text(_HAND_AUTHORED_BASH, encoding="utf-8", newline="\n")
    script.chmod(0o400)
    return script, tool_root


def _run_fixed_canary(
    bash: str,
    script: Path,
    tool_root: Path,
    workspace: Path,
    route_key: str,
    fallback_policy: str,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [bash, str(script), route_key, fallback_policy],
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
        timeout=10,
    )


def _translate(content: bytes, source: bytes, destination: bytes) -> bytes:
    return content.translate(bytes.maketrans(source, destination))


class CaseRoutedBatchTransformBashCanaryTests(unittest.TestCase):
    def test_fixed_bash_canary_passes_all_100_public_fixtures(self) -> None:
        bash, tools = _binary_paths(self)
        tasks = routed.build_case_routed_batch_transform_tasks()
        self.assertEqual(len(tasks), 20)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, tool_root = _write_fixed_canary(root, tools)
            passed = 0
            for task_index, task in enumerate(tasks):
                self.assertIs(task.candidate_execution_authorized, False)
                self.assertIs(task.model_selection_eligible, False)
                self.assertIs(task.claim_authorized, False)
                for profile_index, profile in enumerate(
                    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
                ):
                    bundle = routed.build_case_routed_batch_transform_fixture_bundle(
                        task, profile
                    )
                    self.assertIs(bundle.candidate_execution_authorized, False)
                    self.assertIs(bundle.model_selection_eligible, False)
                    self.assertIs(bundle.claim_authorized, False)
                    workspace = (
                        root / "workspaces" / f"{task_index:02d}-{profile_index}"
                    )
                    with self.subTest(
                        route_key=task.parameters.route_key,
                        fallback=task.parameters.fallback_policy,
                        profile=profile.profile_id,
                    ), routed.materialize_case_routed_batch_transform_fixture(
                        task, profile, bundle, workspace
                    ) as handle:
                        completed = _run_fixed_canary(
                            bash,
                            script,
                            tool_root,
                            workspace,
                            task.parameters.route_key,
                            task.parameters.fallback_policy,
                        )
                        self.assertEqual(
                            completed.returncode,
                            0,
                            completed.stdout + completed.stderr,
                        )
                        self.assertEqual(completed.stdout, b"")
                        self.assertEqual(completed.stderr, b"")
                        self.assertTrue(
                            routed.verify_case_routed_batch_transform_workspace(
                                task, profile, bundle, handle
                            )
                        )
                        passed += 1
            self.assertEqual(passed, 100)

    def test_full_byte_nul_leading_missing_lf_streams_are_exact(self) -> None:
        bash, tools = _binary_paths(self)
        all_bytes = bytes(range(256))
        self.assertEqual(
            sha256(all_bytes).hexdigest(),
            "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880",
        )
        self.assertEqual(all_bytes[:1], b"\x00")
        self.assertNotEqual(all_bytes[-1:], b"\n")
        self.assertIn(b"\t", all_bytes)
        self.assertIn(b"\r", all_bytes)
        with self.assertRaises(UnicodeDecodeError):
            all_bytes.decode("utf-8", errors="strict")

        payloads = {
            "full-upper": b"U" + all_bytes,
            "full-lower": b"L" + all_bytes,
            "full-detab": b"T" + all_bytes,
            "full-strip": b"C" + all_bytes,
            "all-bytes": all_bytes,
            "invalid-first": b"\xffU\x00\xc3(\tkeep\rno-final-lf",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, tool_root = _write_fixed_canary(root, tools)
            workspace = root / "binary-workspace"
            payload_root = workspace / "input/batch/payloads"
            payload_root.mkdir(parents=True)
            rows: list[bytes] = []
            for identifier, content in payloads.items():
                source = payload_root / f"{identifier}.bin"
                source.write_bytes(content)
                source.chmod(0o400)
                rows.append(
                    (
                        f"{identifier}\tinput/batch/payloads/{identifier}.bin\t"
                        "opaque\tpreserve\n"
                    ).encode("utf-8")
                )
            manifest = workspace / "input/batch/manifest.tsv"
            manifest.write_bytes(
                b"".join((rows[4], rows[0], rows[3], rows[0], rows[5], rows[2], rows[1]))
            )
            manifest.chmod(0o400)
            input_snapshot = {
                path.relative_to(workspace).as_posix(): (
                    path.read_bytes(),
                    stat.S_IMODE(path.stat().st_mode),
                    path.stat().st_mtime_ns,
                    path.stat().st_nlink,
                )
                for path in (workspace / "input").rglob("*")
                if path.is_file()
            }

            completed = _run_fixed_canary(
                bash,
                script,
                tool_root,
                workspace,
                "leading-byte",
                "copy-verbatim",
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stdout + completed.stderr,
            )
            self.assertEqual(completed.stdout, b"")
            self.assertEqual(completed.stderr, b"")

            expected = {
                "output/routes/upper/full-upper.out": _translate(
                    payloads["full-upper"],
                    b"abcdefghijklmnopqrstuvwxyz",
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                ),
                "output/routes/lower/full-lower.out": _translate(
                    payloads["full-lower"],
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                    b"abcdefghijklmnopqrstuvwxyz",
                ),
                "output/routes/detab/full-detab.out": payloads[
                    "full-detab"
                ].replace(b"\t", b"    "),
                "output/routes/strip-cr/full-strip.out": payloads[
                    "full-strip"
                ].replace(b"\r", b""),
                "output/routes/verbatim/all-bytes.out": all_bytes,
                "output/routes/verbatim/invalid-first.out": payloads[
                    "invalid-first"
                ],
                "output/errors.tsv": b"",
                "output/status.tsv": b"batch\tcomplete\t6\t4\t2\t6\t0\n",
            }
            observed: dict[str, bytes] = {}
            for path in (workspace / "output").rglob("*"):
                relative = path.relative_to(workspace).as_posix()
                info = path.lstat()
                self.assertFalse(path.is_symlink(), relative)
                if path.is_dir():
                    self.assertEqual(stat.S_IMODE(info.st_mode), 0o755, relative)
                else:
                    self.assertTrue(path.is_file(), relative)
                    self.assertEqual(stat.S_IMODE(info.st_mode), 0o644, relative)
                    self.assertEqual(info.st_nlink, 1, relative)
                    observed[relative] = path.read_bytes()
            self.assertEqual(observed, expected)
            self.assertEqual(
                sha256(observed["output/routes/verbatim/all-bytes.out"]).hexdigest(),
                sha256(all_bytes).hexdigest(),
            )
            final_snapshot = {
                path.relative_to(workspace).as_posix(): (
                    path.read_bytes(),
                    stat.S_IMODE(path.stat().st_mode),
                    path.stat().st_mtime_ns,
                    path.stat().st_nlink,
                )
                for path in (workspace / "input").rglob("*")
                if path.is_file()
            }
            self.assertEqual(final_snapshot, input_snapshot)

    def test_canary_does_not_widen_family_authority_or_observability(self) -> None:
        tasks = routed.build_case_routed_batch_transform_tasks()
        self.assertTrue(
            all(
                task.candidate_execution_authorized is False
                and task.model_selection_eligible is False
                and task.claim_authorized is False
                for task in tasks
            )
        )
        self.assertIs(routed.CASE_ROUTED_BATCH_TRANSFORM_TOOL_HISTORY_OBSERVED, False)
        self.assertIs(routed.CASE_ROUTED_BATCH_TRANSFORM_READ_SCOPE_OBSERVED, False)
        self.assertIs(routed.CASE_ROUTED_BATCH_TRANSFORM_ROUTE_HISTORY_OBSERVED, False)
        self.assertIs(
            routed.CASE_ROUTED_BATCH_TRANSFORM_TRANSFORM_HISTORY_OBSERVED,
            False,
        )
        self.assertIs(
            routed.CASE_ROUTED_BATCH_TRANSFORM_ATOMIC_PUBLICATION_HISTORY_OBSERVED,
            False,
        )
        self.assertIs(
            routed.CASE_ROUTED_BATCH_TRANSFORM_CANDIDATE_EXIT_STATUS_OBSERVED,
            False,
        )
        self.assertNotIn("/usr/bin/", _HAND_AUTHORED_BASH)
        self.assertNotIn("/bin/", _HAND_AUTHORED_BASH)


if __name__ == "__main__":
    unittest.main()
