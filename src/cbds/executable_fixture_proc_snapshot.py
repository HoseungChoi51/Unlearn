"""Deterministic synthetic process-snapshot fixtures for method development.

The public task models a deliberately small, static subset of ``/proc`` below
``input/proc-snapshot``.  This private builder parses only immutable fixture
records: it never opens the host filesystem, reads live ``/proc``, or starts a
process.  Malformed, inaccessible, noncanonical-PID, and irrelevant entries
remain in the input tree as adversarial decoys.
"""

from __future__ import annotations

import json
from pathlib import PurePosixPath
import re
from typing import Final

from .executable_fixture_bundle import (
    ExecutableFixtureBundle,
    OracleOutputRecord,
    build_executable_fixture_bundle,
    build_trusted_fixture_oracle,
)
from .executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
    ExecutableFixtureProfile,
)
from .executable_static_types import (
    ExecutableStaticTask,
    ProcSnapshotReportParameters,
)
from .executable_workspace import (
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
)


PROC_SNAPSHOT_FIXTURE_GENERATOR_VERSION: Final[str] = "1.0.0"
PROC_SNAPSHOT_ROOT: Final[PurePosixPath] = PurePosixPath(
    "input/proc-snapshot"
)
OUTPUT_PATH: Final[str] = "output/processes.jsonl"
OUTPUT_MODE: Final[int] = 0o644
OUTPUT_MAXIMUM_BYTES: Final[int] = 256 * 1024
_READ_BITS: Final[int] = 0o444
_CANONICAL_PID_RE: Final[re.Pattern[str]] = re.compile(r"[1-9][0-9]*\Z")
_STATUS_KEYS: Final[frozenset[str]] = frozenset(
    {"pid", "ppid", "uid", "rss_kib", "state", "comm"}
)
_STATES: Final[frozenset[str]] = frozenset({"R", "S", "D", "Z", "T", "I"})
_MAXIMUM_SAFE_JSON_INTEGER: Final[int] = 9_007_199_254_740_991


class ExecutableFixtureProcSnapshotError(ValueError):
    """Raised when a process-snapshot fixture is outside its closed contract."""


class _MalformedStatus(ValueError):
    """Internal marker for a status record that must be ignored."""


def _validate_task_profile(
    task: object, profile: object
) -> tuple[
    ExecutableStaticTask,
    ExecutableFixtureProfile,
    ProcSnapshotReportParameters,
]:
    if (
        type(task) is not ExecutableStaticTask
        or task.family_id != "proc-snapshot-report"
        or type(task.parameters) is not ProcSnapshotReportParameters
    ):
        raise ExecutableFixtureProcSnapshotError(
            "task must be an exact proc-snapshot-report ExecutableStaticTask"
        )
    if type(profile) is not ExecutableFixtureProfile:
        raise ExecutableFixtureProcSnapshotError(
            "profile must be an exact ExecutableFixtureProfile"
        )
    try:
        parameters = ProcSnapshotReportParameters(
            view=task.parameters.view,
            predicate=task.parameters.predicate,
        )
        task.__post_init__()
        reconstructed_profile = ExecutableFixtureProfile(
            profile_id=profile.profile_id,
            cases=profile.cases,
            profile_sha256=profile.profile_sha256,
            profile_version=profile.profile_version,
            public_method_development=profile.public_method_development,
            sealed=profile.sealed,
            candidate_execution_authorized=profile.candidate_execution_authorized,
            model_selection_eligible=profile.model_selection_eligible,
            claim_authorized=profile.claim_authorized,
        )
    except (TypeError, ValueError) as exc:
        raise ExecutableFixtureProcSnapshotError(
            "task or profile failed closed-contract revalidation"
        ) from exc
    if reconstructed_profile not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        raise ExecutableFixtureProcSnapshotError(
            "profile is not public method-development data"
        )
    return task, profile, parameters


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ExecutableFixtureProcSnapshotError(
            "fixture record cannot be encoded as canonical scalar UTF-8 JSON"
        ) from exc


def _status(
    pid: int,
    *,
    ppid: int,
    uid: int,
    rss_kib: int,
    state: str,
    comm: str,
) -> bytes:
    return _canonical_json_bytes(
        {
            "pid": pid,
            "ppid": ppid,
            "uid": uid,
            "rss_kib": rss_kib,
            "state": state,
            "comm": comm,
        }
    )


def _cmdline(*arguments: str) -> bytes:
    return b"".join(
        argument.encode("utf-8", errors="strict") + b"\0"
        for argument in arguments
    )


def _spaces_unicode_inputs() -> tuple[InputFile | InputSymlink, ...]:
    return (
        InputFile(
            "input/proc-snapshot/2/status.json",
            _status(
                2,
                ppid=0,
                uid=0,
                rss_kib=1536,
                state="R",
                comm="shell café 雪",
            ),
            0o640,
        ),
        InputFile(
            "input/proc-snapshot/2/cmdline.bin",
            _cmdline("bash", "-lc", "printf café 雪"),
            0o440,
        ),
        InputFile(
            "input/proc-snapshot/10/status.json",
            _status(
                10,
                ppid=2,
                uid=1000,
                rss_kib=4096,
                state="S",
                comm="worker with spaces",
            ),
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/10/cmdline.bin",
            _cmdline("/opt/worker 雪", "argument with spaces", "café"),
            0o400,
        ),
        InputFile(
            "input/proc-snapshot/41/status.json",
            _status(
                41,
                ppid=2,
                uid=0,
                rss_kib=0,
                state="Z",
                comm="finished 雪",
            ),
            0o404,
        ),
        # Invalid comm and noncanonical PID-directory decoys.
        InputFile(
            "input/proc-snapshot/5/status.json",
            _status(
                5,
                ppid=2,
                uid=1000,
                rss_kib=8,
                state="S",
                comm="bad\ncomm",
            ),
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/02/status.json",
            _status(
                2,
                ppid=0,
                uid=0,
                rss_kib=1,
                state="R",
                comm="noncanonical pid directory",
            ),
            0o444,
        ),
        InputFile(
            "input/outside/13/status.json",
            _status(
                13,
                ppid=2,
                uid=0,
                rss_kib=12,
                state="R",
                comm="outside root",
            ),
            0o444,
        ),
    )


def _leading_dashes_globs_inputs() -> tuple[InputFile | InputSymlink, ...]:
    return (
        InputFile(
            "input/proc-snapshot/3/status.json",
            _status(
                3,
                ppid=0,
                uid=0,
                rss_kib=256,
                state="R",
                comm="-leading-shell",
            ),
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/3/cmdline.bin",
            _cmdline("-dash", "*", "[abc]?", "--flag=*"),
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/20/status.json",
            _status(
                20,
                ppid=3,
                uid=2000,
                rss_kib=8192,
                state="D",
                comm="[worker]*?",
            ),
            0o404,
        ),
        InputFile(
            "input/proc-snapshot/20/cmdline.bin",
            _cmdline("literal[glob]", "?", "--", "[x]*"),
            0o440,
        ),
        InputFile(
            "input/proc-snapshot/100/status.json",
            _status(
                100,
                ppid=3,
                uid=0,
                rss_kib=64,
                state="Z",
                comm="*zombie?",
            ),
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/-4/status.json",
            _status(
                4,
                ppid=3,
                uid=0,
                rss_kib=4,
                state="R",
                comm="dash-dir-decoy",
            ),
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/[5]/status.json",
            _status(
                5,
                ppid=3,
                uid=0,
                rss_kib=5,
                state="R",
                comm="glob-dir-decoy",
            ),
            0o444,
        ),
        InputSymlink(
            "input/proc-snapshot/3/status-link.json",
            "status.json",
        ),
        InputSymlink(
            "input/proc-snapshot/3/cmdline-link.bin",
            "cmdline.bin",
        ),
    )


def _empty_duplicates_inputs() -> tuple[InputFile | InputSymlink, ...]:
    statuses = (
        (1, 0, 0, 128, "R", "repeater"),
        (4, 1, 1000, 0, "S", "empty cmdline"),
        (8, 1, 1000, 64, "Z", "empty argument"),
        (12, 1, 0, 32, "D", "unterminated"),
        (13, 1, 1000, 16, "T", "invalid utf8"),
        (16, 1, 1000, 8, "I", "only empty argument"),
    )
    entries: list[InputFile | InputSymlink] = [
        InputFile(
            f"input/proc-snapshot/{pid}/status.json",
            _status(
                pid,
                ppid=ppid,
                uid=uid,
                rss_kib=rss_kib,
                state=state,
                comm=comm,
            ),
            0o444,
        )
        for pid, ppid, uid, rss_kib, state, comm in statuses
    ]
    entries.extend(
        (
            InputFile(
                "input/proc-snapshot/1/cmdline.bin",
                _cmdline("duplicate", "duplicate", "--same"),
                0o444,
            ),
            InputFile("input/proc-snapshot/4/cmdline.bin", b"", 0o444),
            InputFile(
                "input/proc-snapshot/8/cmdline.bin",
                b"argument\0\0",
                0o444,
            ),
            InputFile(
                "input/proc-snapshot/12/cmdline.bin",
                b"not-terminated",
                0o444,
            ),
            InputFile(
                "input/proc-snapshot/13/cmdline.bin",
                b"valid\0\xff\0",
                0o444,
            ),
            InputFile("input/proc-snapshot/16/cmdline.bin", b"\0", 0o444),
        )
    )
    return tuple(entries)


def _symlinks_ordering_inputs() -> tuple[InputFile | InputSymlink, ...]:
    # Deliberately put PID 100 before 10 before 2.  Oracle order is numeric.
    return (
        InputFile(
            "input/proc-snapshot/100/cmdline.bin",
            _cmdline("hundred", "--later"),
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/100/status.json",
            _status(
                100,
                ppid=10,
                uid=1000,
                rss_kib=100,
                state="S",
                comm="hundred",
            ),
            0o444,
        ),
        InputSymlink(
            "input/proc-snapshot/status-for-10.json",
            "10/status.json",
        ),
        InputFile(
            "input/proc-snapshot/10/cmdline.bin",
            _cmdline("ten", "argument with spaces"),
            0o440,
        ),
        InputFile(
            "input/proc-snapshot/10/status.json",
            _status(
                10,
                ppid=2,
                uid=0,
                rss_kib=10,
                state="R",
                comm="ten",
            ),
            0o440,
        ),
        InputSymlink(
            "input/proc-snapshot/10/status-link.json",
            "status.json",
        ),
        InputSymlink(
            "input/proc-snapshot/10/cmdline-link.bin",
            "cmdline.bin",
        ),
        # Exact consulted basenames as symlinks: following either changes the
        # semantic answer and therefore exercises the public no-follow rule.
        InputFile(
            "input/proc-snapshot/30/real-status.json",
            _status(
                30,
                ppid=10,
                uid=0,
                rss_kib=30,
                state="R",
                comm="symlink-status-decoy",
            ),
            0o444,
        ),
        InputSymlink(
            "input/proc-snapshot/30/status.json",
            "real-status.json",
        ),
        InputFile(
            "input/proc-snapshot/40/status.json",
            _status(
                40,
                ppid=10,
                uid=1000,
                rss_kib=40,
                state="S",
                comm="symlink-cmdline-empty",
            ),
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/40/real-cmdline.bin",
            _cmdline("must-not-follow", "--hidden"),
            0o444,
        ),
        InputSymlink(
            "input/proc-snapshot/40/cmdline.bin",
            "real-cmdline.bin",
        ),
        InputFile(
            "input/proc-snapshot/2/status.json",
            _status(
                2,
                ppid=0,
                uid=0,
                rss_kib=2,
                state="Z",
                comm="two",
            ),
            0o404,
        ),
        InputFile(
            "input/proc-snapshot/007/status.json",
            _status(
                7,
                ppid=2,
                uid=0,
                rss_kib=7,
                state="R",
                comm="leading-zero decoy",
            ),
            0o444,
        ),
    )


def _partial_permissions_inputs() -> tuple[InputFile | InputSymlink, ...]:
    return (
        InputFile(
            "input/proc-snapshot/6/status.json",
            _status(
                6,
                ppid=0,
                uid=0,
                rss_kib=600,
                state="R",
                comm="permission anchor",
            ),
            0o400,
        ),
        InputFile(
            "input/proc-snapshot/6/cmdline.bin",
            _cmdline("anchor", "--readable"),
            0o400,
        ),
        # A valid but mode-unreadable status cannot form a snapshot.
        InputFile(
            "input/proc-snapshot/9/status.json",
            _status(
                9,
                ppid=6,
                uid=0,
                rss_kib=900,
                state="R",
                comm="unreadable status",
            ),
            0o000,
        ),
        # Missing status: the directory exists only because cmdline.bin does.
        InputFile(
            "input/proc-snapshot/11/cmdline.bin",
            _cmdline("missing-status"),
            0o444,
        ),
        InputFile("input/proc-snapshot/13/status.json", b"{malformed", 0o444),
        InputFile(
            "input/proc-snapshot/15/status.json",
            _status(
                15,
                ppid=6,
                uid=1000,
                rss_kib=15,
                state="S",
                comm="bad\rcomm",
            ),
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/17/status.json",
            (
                b'{"comm":"duplicate pid","pid":17,"pid":17,'
                b'"ppid":6,"rss_kib":17,"state":"S","uid":1000}'
            ),
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/18/status.json",
            b'{"comm":"missing rss","pid":18,"ppid":6,"state":"S","uid":0}',
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/19/status.json",
            _status(
                19,
                ppid=6,
                uid=1000,
                rss_kib=1900,
                state="S",
                comm="unreadable cmdline",
            ),
            0o404,
        ),
        InputFile(
            "input/proc-snapshot/19/cmdline.bin",
            _cmdline("must-not-be-visible"),
            0o000,
        ),
        InputFile(
            "input/proc-snapshot/21/status.json",
            _status(
                21,
                ppid=6,
                uid=0,
                rss_kib=2100,
                state="Z",
                comm="invalid cmdline framing",
            ),
            0o440,
        ),
        InputFile(
            "input/proc-snapshot/21/cmdline.bin",
            b"missing-final-nul",
            0o440,
        ),
        InputFile(
            "input/proc-snapshot/22/status.json",
            _status(
                23,
                ppid=6,
                uid=0,
                rss_kib=22,
                state="R",
                comm="pid mismatch",
            ),
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/23/status.json",
            (
                b'{"comm":"boolean uid","pid":23,"ppid":6,'
                b'"rss_kib":23,"state":"R","uid":true}'
            ),
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/24/status.json",
            _status(
                24,
                ppid=6,
                uid=0,
                rss_kib=24,
                state="X",
                comm="bad state",
            ),
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/25/status.json",
            b'{"comm":"bad-utf8-\xff","pid":25,"ppid":6,'
            b'"rss_kib":25,"state":"R","uid":0}',
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/27/status.json",
            b'{"comm":"nonfinite","pid":27,"ppid":6,'
            b'"rss_kib":NaN,"state":"R","uid":0}',
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/28/status.json",
            b'{"comm":"extra key","extra":0,"pid":28,"ppid":6,'
            b'"rss_kib":28,"state":"R","uid":0}',
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/29/status.json",
            b'{"comm":"negative ppid","pid":29,"ppid":-1,'
            b'"rss_kib":29,"state":"R","uid":0}',
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/30/status.json",
            b'{"comm":30,"pid":30,"ppid":6,'
            b'"rss_kib":30,"state":"R","uid":0}',
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/31/status.json",
            b'{"comm":"exponent","pid":31,"ppid":6,'
            b'"rss_kib":1e2,"state":"R","uid":0}',
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/32/status.json",
            b'{"comm":"unsafe integer","pid":32,"ppid":6,'
            b'"rss_kib":9007199254740992,"state":"R","uid":0}',
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/33/status.json",
            b'{"comm":"negative zero","pid":33,"ppid":-0,'
            b'"rss_kib":33,"state":"R","uid":0}',
            0o444,
        ),
        InputFile(
            "input/proc-snapshot/not-a-pid/status.json",
            _status(
                26,
                ppid=6,
                uid=0,
                rss_kib=26,
                state="R",
                comm="non-pid directory",
            ),
            0o444,
        ),
    )


def _fixture_inputs(
    profile: ExecutableFixtureProfile,
) -> tuple[InputFile | InputSymlink, ...]:
    if profile.profile_id == "spaces-unicode":
        return _spaces_unicode_inputs()
    if profile.profile_id == "leading-dashes-globs":
        return _leading_dashes_globs_inputs()
    if profile.profile_id == "empty-duplicates":
        return _empty_duplicates_inputs()
    if profile.profile_id == "symlinks-ordering":
        return _symlinks_ordering_inputs()
    if profile.profile_id == "partial-permissions":
        return _partial_permissions_inputs()
    raise ExecutableFixtureProcSnapshotError("unsupported fixture profile")


def _reject_json_constant(_value: str) -> object:
    raise _MalformedStatus("non-finite JSON constant")


def _reject_json_float(_value: str) -> object:
    raise _MalformedStatus("status number is not a canonical integer")


def _safe_json_integer(value: str) -> int:
    if len(value) > 17:
        raise _MalformedStatus("status integer exceeds its parser bound")
    parsed = int(value, 10)
    if (
        str(parsed) != value
        or not 0 <= parsed <= _MAXIMUM_SAFE_JSON_INTEGER
    ):
        raise _MalformedStatus("status integer is not canonical and safe")
    return parsed


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _MalformedStatus("duplicate JSON object key")
        result[key] = value
    return result


def _parse_status(content: bytes, directory_pid: int) -> dict[str, object] | None:
    try:
        text = content.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
            parse_float=_reject_json_float,
            parse_int=_safe_json_integer,
        )
    except (UnicodeDecodeError, RecursionError, ValueError):
        return None
    if type(value) is not dict or set(value) != _STATUS_KEYS:
        return None
    for field in ("pid", "ppid", "uid", "rss_kib"):
        if type(value.get(field)) is not int or value[field] < 0:
            return None
    if value["pid"] != directory_pid:
        return None
    state = value.get("state")
    comm = value.get("comm")
    if type(state) is not str or state not in _STATES:
        return None
    if (
        type(comm) is not str
        or any(character in comm for character in "\0\r\n")
    ):
        return None
    try:
        comm.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return None
    return value


def _parse_cmdline(item: InputFile | InputSymlink | None) -> tuple[str, ...]:
    if type(item) is not InputFile or item.mode & _READ_BITS == 0:
        return ()
    content = item.content
    if not content or not content.endswith(b"\0"):
        return ()
    encoded_arguments = content[:-1].split(b"\0")
    if not encoded_arguments or any(not argument for argument in encoded_arguments):
        return ()
    try:
        return tuple(
            argument.decode("utf-8", errors="strict")
            for argument in encoded_arguments
        )
    except UnicodeDecodeError:
        return ()


def _predicate_matches(
    status: dict[str, object], argv: tuple[str, ...], predicate: str
) -> bool:
    if predicate == "all-valid":
        return True
    if predicate == "running-only":
        return status["state"] == "R"
    if predicate == "non-zombie":
        return status["state"] != "Z"
    if predicate == "uid-zero":
        return status["uid"] == 0
    if predicate == "has-argv":
        return bool(argv)
    raise ExecutableFixtureProcSnapshotError("unsupported process predicate")


def _project_row(
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
    raise ExecutableFixtureProcSnapshotError("unsupported process view")


def _derive_output_content(
    inputs: tuple[InputFile | InputSymlink, ...],
    parameters: ProcSnapshotReportParameters,
) -> bytes:
    by_path = {item.path: item for item in inputs}
    rows: list[tuple[int, dict[str, object]]] = []
    for item in inputs:
        if type(item) is not InputFile or item.mode & _READ_BITS == 0:
            continue
        path = PurePosixPath(item.path)
        if (
            len(path.parts) != 4
            or path.parts[:2] != PROC_SNAPSHOT_ROOT.parts
            or path.name != "status.json"
        ):
            continue
        pid_text = path.parts[2]
        if _CANONICAL_PID_RE.fullmatch(pid_text) is None:
            continue
        pid = int(pid_text, 10)
        status = _parse_status(item.content, pid)
        if status is None:
            continue
        cmdline_path = (path.parent / "cmdline.bin").as_posix()
        argv = _parse_cmdline(by_path.get(cmdline_path))
        if not _predicate_matches(status, argv, parameters.predicate):
            continue
        rows.append((pid, _project_row(status, argv, parameters.view)))
    rows.sort(key=lambda item: item[0])
    return b"".join(_canonical_json_bytes(row) + b"\n" for _pid, row in rows)


def build_proc_snapshot_report_fixture_bundle(
    task: ExecutableStaticTask,
    profile: ExecutableFixtureProfile,
) -> ExecutableFixtureBundle:
    """Build one nonexecuting, content-bound synthetic process fixture."""

    task, profile, parameters = _validate_task_profile(task, profile)
    inputs = _fixture_inputs(profile)
    content = _derive_output_content(inputs, parameters)
    if len(content) > OUTPUT_MAXIMUM_BYTES:
        raise ExecutableFixtureProcSnapshotError(
            "derived process report exceeds its output bound"
        )
    definition = FixtureDefinition(
        fixture_id=f"dev.proc-snapshot-report.{profile.profile_id}",
        inputs=inputs,
        expected_files=(
            ExpectedFile(
                OUTPUT_PATH,
                maximum_bytes=OUTPUT_MAXIMUM_BYTES,
                mode=OUTPUT_MODE,
            ),
        ),
    )
    oracle = build_trusted_fixture_oracle(
        (OracleOutputRecord(OUTPUT_PATH, content, OUTPUT_MODE),),
        semantic_verifier_identity="verify-proc-snapshot-report-v1",
    )
    return build_executable_fixture_bundle(
        task_contract_sha256=task.task_contract_sha256,
        profile_sha256=profile.profile_sha256,
        definition=definition,
        oracle=oracle,
    )


__all__ = [
    "PROC_SNAPSHOT_FIXTURE_GENERATOR_VERSION",
    "OUTPUT_MAXIMUM_BYTES",
    "ExecutableFixtureProcSnapshotError",
    "build_proc_snapshot_report_fixture_bundle",
]
