"""Fail-closed preflight for a non-scored Bubblewrap development backend.

This module is intentionally separate from :mod:`cbds.runtime_preflight` and
the Docker/Podman scored sandbox contract.  It may run one fixed, harmless
namespace canary when the caller explicitly requests it.  It never authorizes
candidate execution: the trusted PID-1 supervisor and child-only seccomp
filter required for that boundary are not implemented yet.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import pwd
import re
import selectors
import shutil
import signal
import stat
import subprocess
from time import monotonic
from typing import Final


DEVELOPMENT_PREFLIGHT_SCHEMA_VERSION: Final[str] = "1.0.0"
DEVELOPMENT_PREFLIGHT_VERSION: Final[str] = "1.0.0"
DEVELOPMENT_BACKEND: Final[str] = "bubblewrap-user-systemd"
DEVELOPMENT_SCOPE: Final[str] = "public_method_development_only"
CANARY_UNIT: Final[str] = "cbds-public-development-canary-v1.service"
_SAFE_PATH: Final[str] = (
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)
_EXECUTABLE_NAMES: Final[tuple[str, ...]] = (
    "bwrap",
    "systemd-run",
    "systemctl",
    "bash",
)
_PERMANENT_CANDIDATE_BLOCKERS: Final[tuple[str, ...]] = (
    "blocked_trusted_pid1_supervisor_missing",
    "blocked_child_seccomp_filter_missing",
    "blocked_cgroup_cpu_time_watcher_missing",
    "blocked_bounded_candidate_capture_missing",
    "blocked_quiescence_enforcer_missing",
    "blocked_exact_tool_policy_missing",
    "blocked_host_usr_unpinned",
)


class DevelopmentPreflightError(ValueError):
    """Raised for malformed caller input, never host unavailability."""


@dataclass(frozen=True, slots=True)
class DevelopmentPreflightLimits:
    """Resource ceilings for the fixed harmless canary."""

    timeout_seconds: float = 5.0
    kill_grace_seconds: float = 1.0
    max_output_bytes: int = 64 * 1024
    max_executable_bytes: int = 512 * 1024 * 1024
    memory_bytes: int = 32 * 1024 * 1024
    workspace_bytes: int = 16 * 1024 * 1024
    pids: int = 16
    open_files: int = 32
    cpu_quota_percent: int = 100

    def __post_init__(self) -> None:
        for name in ("timeout_seconds", "kill_grace_seconds"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or value <= 0
                or value > 60
            ):
                raise ValueError(f"{name} must be a finite number in (0, 60]")
        integer_minima = {
            "max_output_bytes": 1,
            "max_executable_bytes": 1,
            "memory_bytes": 6 * 1024 * 1024,
            "workspace_bytes": 1024 * 1024,
            "pids": 2,
            "open_files": 3,
            "cpu_quota_percent": 1,
        }
        for name, minimum in integer_minima.items():
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
                raise ValueError(f"{name} must be an integer >= {minimum}")
        if self.cpu_quota_percent > 1000:
            raise ValueError("cpu_quota_percent must be <= 1000")

    def to_record(self) -> dict[str, int | float]:
        return {
            "timeout_seconds": float(self.timeout_seconds),
            "kill_grace_seconds": float(self.kill_grace_seconds),
            "max_output_bytes_per_stream": self.max_output_bytes,
            "max_executable_bytes": self.max_executable_bytes,
            "memory_bytes": self.memory_bytes,
            "workspace_bytes": self.workspace_bytes,
            "pids": self.pids,
            "open_files": self.open_files,
            "cpu_quota_percent": self.cpu_quota_percent,
        }


@dataclass(frozen=True, slots=True)
class DevelopmentExecutableIdentity:
    """Stable content identity for one trusted host-side executable."""

    name: str
    resolved_path: str
    bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class DevelopmentCommandResult:
    """Bounded observation from the fixed harmless canary command."""

    returncode: int | None
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    output_truncated: bool = False
    launch_error: bool = False

    def __post_init__(self) -> None:
        if self.returncode is not None and (
            isinstance(self.returncode, bool) or not isinstance(self.returncode, int)
        ):
            raise TypeError("returncode must be an integer or None")
        if not isinstance(self.stdout, bytes) or not isinstance(self.stderr, bytes):
            raise TypeError("stdout and stderr must be bytes")
        for name in ("timed_out", "output_truncated", "launch_error"):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"{name} must be boolean")


ExecutableProbe = Callable[[str, str, int], DevelopmentExecutableIdentity]
CanaryRunner = Callable[..., DevelopmentCommandResult]


# This is trusted, fixed canary input.  It contains no candidate-controlled
# bytes and is sent on stdin, never interpolated into argv.
HARMELESS_CANARY_STDIN: Final[bytes] = b"""\
set -eu
uid=$(/usr/bin/id -u)
gid=$(/usr/bin/id -g)
cap_eff=
no_new_privs=
seccomp=
while read -r key value _; do
  case "$key" in
    CapEff:) cap_eff=$value ;;
    NoNewPrivs:) no_new_privs=$value ;;
    Seccomp:) seccomp=$value ;;
  esac
done < /proc/self/status
interface_count=0
non_loopback_interfaces=0
{
  IFS= read -r _ || :
  IFS= read -r _ || :
  while IFS=: read -r interface _; do
    interface=${interface//[[:space:]]/}
    interface_count=$((interface_count + 1))
    [ "$interface" = lo ] || non_loopback_interfaces=$((non_loopback_interfaces + 1))
  done
} < /proc/net/dev
workspace_type=$(/usr/bin/stat -f -c %T /workspace)
block_size=$(/usr/bin/stat -f -c %S /workspace)
block_count=$(/usr/bin/stat -f -c %b /workspace)
workspace_capacity_bytes=$((block_size * block_count))
nested_userns_succeeded=0
if /usr/bin/unshare --user /usr/bin/true 2>/dev/null; then
  nested_userns_succeeded=1
fi
root_writable=0
if : 2>/dev/null > /.cbds-development-root-write-probe; then
  root_writable=1
  /usr/bin/rm -f -- /.cbds-development-root-write-probe
fi
host_home_visible=0
[ ! -e /home ] || host_home_visible=1
host_sys_visible=0
[ ! -e /sys ] || host_sys_visible=1
/usr/bin/printf '{"schema_version":"1.0.0","uid":%s,"gid":%s,"cap_eff":"%s","no_new_privs":%s,"seccomp":%s,"interface_count":%s,"non_loopback_interfaces":%s,"workspace_type":"%s","workspace_capacity_bytes":%s,"nested_userns_succeeded":%s,"root_writable":%s,"host_home_visible":%s,"host_sys_visible":%s}\n' "$uid" "$gid" "$cap_eff" "$no_new_privs" "$seccomp" "$interface_count" "$non_loopback_interfaces" "$workspace_type" "$workspace_capacity_bytes" "$nested_userns_succeeded" "$root_writable" "$host_home_visible" "$host_sys_visible"
"""


def canonical_json_bytes(value: object) -> bytes:
    """Return the canonical JSON bytes used for report identity."""

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise DevelopmentPreflightError("value is not canonical JSON") from exc


def compute_development_preflight_sha256(report: Mapping[str, object]) -> str:
    """Hash a report after excluding its self-referential digest."""

    if not isinstance(report, Mapping):
        raise TypeError("report must be a mapping")
    payload = dict(report)
    payload.pop("report_sha256", None)
    return sha256(canonical_json_bytes(payload)).hexdigest()


def verify_development_preflight_sha256(report: Mapping[str, object]) -> bool:
    """Return whether the report carries a valid canonical self-digest."""

    if not isinstance(report, Mapping):
        return False
    digest = report.get("report_sha256")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        return False
    try:
        return digest == compute_development_preflight_sha256(report)
    except (DevelopmentPreflightError, TypeError):
        return False


def build_harmless_canary_argv(
    *,
    systemd_run: str,
    bwrap: str,
    bash: str,
    limits: DevelopmentPreflightLimits | None = None,
) -> tuple[str, ...]:
    """Build the complete fixed argv for the harmless namespace canary."""

    selected = limits if limits is not None else DevelopmentPreflightLimits()
    if not isinstance(selected, DevelopmentPreflightLimits):
        raise TypeError("limits must be DevelopmentPreflightLimits")
    for name, value in (
        ("systemd_run", systemd_run),
        ("bwrap", bwrap),
        ("bash", bash),
    ):
        _validate_absolute_executable(name, value)
    if not _path_is_below_usr(bash):
        raise DevelopmentPreflightError("bash must resolve below /usr in the minimal root")

    runtime_max = _seconds_text(
        float(selected.timeout_seconds) + float(selected.kill_grace_seconds)
    )
    timeout_stop = _seconds_text(float(selected.kill_grace_seconds))
    properties = (
        f"MemoryMax={selected.memory_bytes}",
        "MemorySwapMax=0",
        f"TasksMax={selected.pids}",
        f"CPUQuota={selected.cpu_quota_percent}%",
        f"LimitNOFILE={selected.open_files}",
        "LimitCORE=0",
        f"RuntimeMaxSec={runtime_max}",
        f"TimeoutStopSec={timeout_stop}",
        "KillMode=control-group",
        "SendSIGKILL=yes",
        "NoNewPrivileges=yes",
        # Bubblewrap needs route netlink while creating the isolated network
        # namespace.  Internet socket families remain unavailable.
        "RestrictAddressFamilies=AF_UNIX AF_NETLINK",
        "UMask=0077",
    )
    argv: list[str] = [
        systemd_run,
        "--user",
        "--wait",
        "--pipe",
        "--collect",
        "--quiet",
        "--service-type=exec",
        f"--unit={CANARY_UNIT}",
    ]
    for item in properties:
        argv.extend(("--property", item))
    argv.extend(
        (
            bwrap,
            "--unshare-all",
            "--unshare-user",
            "--uid",
            "65534",
            "--gid",
            "65534",
            "--disable-userns",
            "--assert-userns-disabled",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--dir",
            "/usr",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/sbin",
            "/sbin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--dir",
            "/etc",
            "--ro-bind-try",
            "/etc/ld.so.cache",
            "/etc/ld.so.cache",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--size",
            str(selected.workspace_bytes),
            "--tmpfs",
            "/workspace",
            "--chmod",
            "0700",
            "/workspace",
            "--setenv",
            "HOME",
            "/workspace",
            "--setenv",
            "TMPDIR",
            "/workspace/tmp",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--setenv",
            "LC_ALL",
            "C.UTF-8",
            "--setenv",
            "TZ",
            "UTC",
            "--chmod",
            "0555",
            "/",
            "--chdir",
            "/workspace",
            bash,
            "--noprofile",
            "--norc",
            "-s",
        )
    )
    return tuple(argv)


def inspect_development_backend(
    *,
    run_harmless_canary: bool = False,
    limits: DevelopmentPreflightLimits | None = None,
    executable_probe: ExecutableProbe | None = None,
    runner: CanaryRunner | None = None,
) -> dict[str, object]:
    """Inspect the development backend and optionally run its fixed canary.

    Candidate execution remains blocked regardless of the result.  The only
    subprocess that this function can express is the fixed canary argv above.
    """

    if not isinstance(run_harmless_canary, bool):
        raise TypeError("run_harmless_canary must be boolean")
    selected_limits = limits if limits is not None else DevelopmentPreflightLimits()
    if not isinstance(selected_limits, DevelopmentPreflightLimits):
        raise TypeError("limits must be DevelopmentPreflightLimits")
    selected_probe = executable_probe if executable_probe is not None else _probe_executable
    selected_runner = runner if runner is not None else _run_harmless_canary

    report: dict[str, object] = {
        "schema_version": DEVELOPMENT_PREFLIGHT_SCHEMA_VERSION,
        "preflight_version": DEVELOPMENT_PREFLIGHT_VERSION,
        "scope": DEVELOPMENT_SCOPE,
        "backend": DEVELOPMENT_BACKEND,
        "public_fixtures_only": True,
        "split_role": "method_development",
        "sealed": False,
        "scored_evaluation_eligible": False,
        "claim_pipeline_eligible": False,
        "tool_policy_enforced": False,
        "candidate_execution_authorized": False,
        "harmless_canary_requested": run_harmless_canary,
        "limits": selected_limits.to_record(),
        "outer_watchdog_contract": {
            "clock": "monotonic",
            "timeout_seconds": float(selected_limits.timeout_seconds),
            "kill_grace_seconds": float(selected_limits.kill_grace_seconds),
            "overflow_detection": "cap_plus_one_per_stream",
            "cleanup": "fixed_systemctl_kill_then_process_group_sigkill",
        },
    }
    blockers = list(_PERMANENT_CANDIDATE_BLOCKERS)
    identities: dict[str, DevelopmentExecutableIdentity] = {}
    identity_records: dict[str, object] = {}
    for name in _EXECUTABLE_NAMES:
        try:
            identity = selected_probe(name, _SAFE_PATH, selected_limits.max_executable_bytes)
            _validate_identity(name, identity, selected_limits)
        except (OSError, TypeError, ValueError):
            identity_records[name] = {"status": "unverified"}
            blockers.append(f"blocked_{name.replace('-', '_')}_unverified")
        else:
            identities[name] = identity
            identity_records[name] = _identity_record(identity)
    report["executables"] = identity_records

    canary: dict[str, object]
    if not run_harmless_canary:
        canary = {"status": "not_requested", "raw_output_retained": False}
        blockers.append("blocked_harmless_canary_not_run")
    elif set(identities) != set(_EXECUTABLE_NAMES):
        canary = {"status": "not_run_unverified_executable", "raw_output_retained": False}
        blockers.append("blocked_harmless_canary_not_run")
    else:
        argv = build_harmless_canary_argv(
            systemd_run=identities["systemd-run"].resolved_path,
            bwrap=identities["bwrap"].resolved_path,
            bash=identities["bash"].resolved_path,
            limits=selected_limits,
        )
        result = _call_runner(
            selected_runner,
            argv,
            HARMELESS_CANARY_STDIN,
            identities["systemctl"].resolved_path,
            selected_limits,
        )
        canary = _canary_record(result, selected_limits)
        if canary["status"] != "passed":
            blockers.append("blocked_harmless_canary_failed")
    report["canary"] = canary

    stable = set(identities) == set(_EXECUTABLE_NAMES)
    for name, before in identities.items():
        try:
            after = selected_probe(name, _SAFE_PATH, selected_limits.max_executable_bytes)
            _validate_identity(name, after, selected_limits)
        except (OSError, TypeError, ValueError):
            current_stable = False
        else:
            current_stable = after == before
        stable = stable and current_stable
        record = identity_records.get(name)
        if isinstance(record, dict):
            record["stable_after_preflight"] = current_stable
        if not current_stable:
            blockers.append(f"blocked_{name.replace('-', '_')}_changed")
    report["all_executables_stable"] = stable
    report["decision"] = {
        "status": "candidate_execution_blocked",
        "blockers": list(dict.fromkeys(blockers)),
    }
    report["report_sha256"] = compute_development_preflight_sha256(report)
    return report


def _seconds_text(value: float) -> str:
    return f"{value:.6f}".rstrip("0").rstrip(".") + "s"


def _path_is_below_usr(value: str) -> bool:
    """Return whether an already-absolute path is strictly below ``/usr``."""

    path = Path(value)
    try:
        path.relative_to("/usr")
    except ValueError:
        return False
    return path != Path("/usr")


def _validate_absolute_executable(name: str, value: str) -> None:
    if (
        not isinstance(value, str)
        or not os.path.isabs(value)
        or value.startswith("//")
        or any(character in value for character in ("\x00", "\r", "\n"))
        or ".." in Path(value).parts
        or str(Path(value)) != value
    ):
        raise DevelopmentPreflightError(f"{name} must be a normalized absolute path")


def _validate_identity(
    name: str,
    identity: DevelopmentExecutableIdentity,
    limits: DevelopmentPreflightLimits,
) -> None:
    if not isinstance(identity, DevelopmentExecutableIdentity) or identity.name != name:
        raise TypeError("executable probe returned the wrong identity")
    _validate_absolute_executable(name, identity.resolved_path)
    if re.fullmatch(r"[0-9a-f]{64}", identity.sha256) is None:
        raise ValueError("invalid executable digest")
    if (
        isinstance(identity.bytes, bool)
        or not isinstance(identity.bytes, int)
        or identity.bytes <= 0
        or identity.bytes > limits.max_executable_bytes
    ):
        raise ValueError("invalid executable size")


def _identity_record(identity: DevelopmentExecutableIdentity) -> dict[str, object]:
    return {
        "status": "verified",
        "resolved_path": identity.resolved_path,
        "bytes": identity.bytes,
        "sha256": identity.sha256,
    }


def _probe_executable(
    name: str, search_path: str, maximum_bytes: int
) -> DevelopmentExecutableIdentity:
    candidate = shutil.which(name, path=search_path)
    if candidate is None:
        raise OSError(f"missing executable: {name}")
    path = Path(candidate).resolve(strict=True)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise OSError(f"executable is not a nonempty regular file: {name}")
    if before.st_size > maximum_bytes:
        raise OSError(f"executable exceeds byte limit: {name}")
    digest = sha256()
    remaining = before.st_size
    with path.open("rb", buffering=0) as handle:
        opened = os.fstat(handle.fileno())
        if _file_snapshot(opened) != _file_snapshot(before):
            raise OSError("executable changed before read")
        while remaining:
            chunk = handle.read(min(1024 * 1024, remaining))
            if not chunk:
                raise OSError("executable ended before snapshotted size")
            digest.update(chunk)
            remaining -= len(chunk)
        if handle.read(1):
            raise OSError("executable grew during read")
        after = os.fstat(handle.fileno())
    if _file_snapshot(after) != _file_snapshot(before):
        raise OSError("executable changed during read")
    return DevelopmentExecutableIdentity(
        name=name,
        resolved_path=str(path),
        bytes=before.st_size,
        sha256=digest.hexdigest(),
    )


def _file_snapshot(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _call_runner(
    runner: CanaryRunner,
    argv: tuple[str, ...],
    stdin: bytes,
    systemctl: str,
    limits: DevelopmentPreflightLimits,
) -> DevelopmentCommandResult:
    try:
        result = runner(
            argv,
            stdin=stdin,
            systemctl=systemctl,
            unit=CANARY_UNIT,
            timeout_seconds=float(limits.timeout_seconds),
            kill_grace_seconds=float(limits.kill_grace_seconds),
            max_output_bytes=limits.max_output_bytes,
        )
    except (OSError, subprocess.SubprocessError, TypeError, ValueError):
        return DevelopmentCommandResult(returncode=None, launch_error=True)
    if not isinstance(result, DevelopmentCommandResult):
        return DevelopmentCommandResult(returncode=None, launch_error=True)
    return result


def _run_harmless_canary(
    argv: tuple[str, ...],
    *,
    stdin: bytes,
    systemctl: str,
    unit: str,
    timeout_seconds: float,
    kill_grace_seconds: float,
    max_output_bytes: int,
) -> DevelopmentCommandResult:
    """Run only the fixed canary with cap+1 capture and an outer watchdog."""

    if stdin != HARMELESS_CANARY_STDIN or unit != CANARY_UNIT:
        raise DevelopmentPreflightError("runner accepts only the fixed harmless canary")
    environment = _clean_user_systemd_environment(os.environ)
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            start_new_session=True,
            env=environment,
        )
    except OSError:
        return DevelopmentCommandResult(returncode=None, launch_error=True)
    if process.stdin is None or process.stdout is None or process.stderr is None:
        _terminate_canary(process, systemctl, unit, kill_grace_seconds)
        return DevelopmentCommandResult(returncode=None, launch_error=True)
    try:
        process.stdin.write(stdin)
        process.stdin.close()
    except (BrokenPipeError, OSError):
        try:
            process.stdin.close()
        except OSError:
            pass

    streams = {
        process.stdout.fileno(): ("stdout", process.stdout),
        process.stderr.fileno(): ("stderr", process.stderr),
    }
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    for descriptor, (_, stream) in streams.items():
        os.set_blocking(descriptor, False)
        selector.register(stream, selectors.EVENT_READ, descriptor)
    deadline = monotonic() + timeout_seconds
    timed_out = False
    truncated = False
    killed = False
    try:
        while selector.get_map():
            remaining = deadline - monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate_canary(process, systemctl, unit, kill_grace_seconds)
                killed = True
                break
            for key, _ in selector.select(min(remaining, 0.05)):
                descriptor = int(key.data)
                name, stream = streams[descriptor]
                available = max_output_bytes - len(buffers[name])
                try:
                    chunk = os.read(descriptor, min(64 * 1024, available + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                if len(chunk) > available:
                    buffers[name].extend(chunk[:available])
                    truncated = True
                    _terminate_canary(process, systemctl, unit, kill_grace_seconds)
                    killed = True
                    break
                buffers[name].extend(chunk)
            if killed:
                break
    finally:
        selector.close()
        for _, stream in streams.values():
            try:
                stream.close()
            except OSError:
                pass
    if not killed and process.poll() is None:
        try:
            process.wait(timeout=kill_grace_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_canary(process, systemctl, unit, kill_grace_seconds)
    try:
        returncode = process.wait(timeout=kill_grace_seconds)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)
        returncode = None
    return DevelopmentCommandResult(
        returncode=returncode,
        stdout=bytes(buffers["stdout"]),
        stderr=bytes(buffers["stderr"]),
        timed_out=timed_out,
        output_truncated=truncated,
    )


def _terminate_canary(
    process: subprocess.Popen[bytes],
    systemctl: str,
    unit: str,
    grace_seconds: float,
) -> None:
    try:
        subprocess.run(
            (
                systemctl,
                "--user",
                "kill",
                "--kill-who=all",
                "--signal=SIGKILL",
                unit,
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            close_fds=True,
            env=_clean_user_systemd_environment(os.environ),
            timeout=max(grace_seconds, 0.1),
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass
    _kill_process_group(process)


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError, PermissionError):
        try:
            process.kill()
        except OSError:
            pass


def _clean_user_systemd_environment(source: Mapping[str, str]) -> dict[str, str]:
    uid = os.getuid()
    runtime = f"/run/user/{uid}"
    environment = {
        "PATH": _SAFE_PATH,
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "XDG_RUNTIME_DIR": runtime,
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime}/bus",
    }
    try:
        home = pwd.getpwuid(uid).pw_dir
    except (KeyError, OSError):
        home = "/nonexistent"
    environment["HOME"] = home if isinstance(home, str) and os.path.isabs(home) else "/nonexistent"
    # Caller-controlled values are deliberately ignored.  The argument exists
    # to make that behavior explicit and injectable in tests.
    del source
    return environment


def _canary_record(
    result: DevelopmentCommandResult,
    limits: DevelopmentPreflightLimits,
) -> dict[str, object]:
    base: dict[str, object] = {
        "returncode": result.returncode,
        "timed_out": result.timed_out,
        "output_truncated": result.output_truncated,
        "stdout_bytes": len(result.stdout),
        "stdout_sha256": sha256(result.stdout).hexdigest(),
        "stderr_bytes": len(result.stderr),
        "stderr_sha256": sha256(result.stderr).hexdigest(),
        "raw_output_retained": False,
    }
    if result.launch_error:
        base["status"] = "launch_error"
        return base
    if result.timed_out:
        base["status"] = "timeout"
        return base
    if result.output_truncated:
        base["status"] = "output_limit_exceeded"
        return base
    if result.returncode != 0 or result.stderr:
        base["status"] = "nonzero_or_stderr"
        return base
    try:
        observation = _load_canary_json(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        base["status"] = "malformed_output"
        return base
    failures = _canary_failures(observation, limits)
    base["status"] = "passed" if not failures else "isolation_mismatch"
    base["isolation_failures"] = failures
    base["observation"] = observation
    return base


def _load_canary_json(payload: bytes) -> dict[str, object]:
    value = json.loads(
        payload.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_nonfinite,
    )
    if not isinstance(value, dict):
        raise ValueError("canary output must be an object")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _canary_failures(
    observation: Mapping[str, object],
    limits: DevelopmentPreflightLimits,
) -> list[str]:
    expected_keys = {
        "schema_version",
        "uid",
        "gid",
        "cap_eff",
        "no_new_privs",
        "seccomp",
        "interface_count",
        "non_loopback_interfaces",
        "workspace_type",
        "workspace_capacity_bytes",
        "nested_userns_succeeded",
        "root_writable",
        "host_home_visible",
        "host_sys_visible",
    }
    failures: list[str] = []
    if set(observation) != expected_keys:
        failures.append("unexpected_observation_shape")
        return failures
    expected_values = {
        "schema_version": "1.0.0",
        "uid": 65534,
        "gid": 65534,
        "cap_eff": "0000000000000000",
        "no_new_privs": 1,
        "non_loopback_interfaces": 0,
        "workspace_type": "tmpfs",
        "nested_userns_succeeded": 0,
        "root_writable": 0,
        "host_home_visible": 0,
        "host_sys_visible": 0,
    }
    for name, expected in expected_values.items():
        if observation.get(name) != expected:
            failures.append(f"{name}_mismatch")
    interface_count = observation.get("interface_count")
    if type(interface_count) is not int or not 0 <= interface_count <= 1:
        failures.append("interface_count_mismatch")
    capacity = observation.get("workspace_capacity_bytes")
    if type(capacity) is not int or not 0 < capacity <= limits.workspace_bytes:
        failures.append("workspace_capacity_mismatch")
    seccomp = observation.get("seccomp")
    if type(seccomp) is not int or seccomp not in (0, 1, 2):
        failures.append("seccomp_observation_invalid")
    return failures


__all__ = [
    "CANARY_UNIT",
    "DEVELOPMENT_BACKEND",
    "DEVELOPMENT_PREFLIGHT_SCHEMA_VERSION",
    "DEVELOPMENT_PREFLIGHT_VERSION",
    "DEVELOPMENT_SCOPE",
    "DevelopmentCommandResult",
    "DevelopmentExecutableIdentity",
    "DevelopmentPreflightError",
    "DevelopmentPreflightLimits",
    "HARMELESS_CANARY_STDIN",
    "build_harmless_canary_argv",
    "canonical_json_bytes",
    "compute_development_preflight_sha256",
    "inspect_development_backend",
    "verify_development_preflight_sha256",
]
