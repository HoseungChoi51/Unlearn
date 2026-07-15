"""Synthesized-candidate-input-free sealed-runtime namespace canary.

This module tests one narrow launch boundary and nothing more.  Regular files
owned by :class:`DevelopmentRuntimeFdSnapshot` are exposed to the user service
manager through ``OpenFile=/proc/<controller>/fd/<fd>``.  The resulting service
descriptors, numbered from three in declaration order, are consumed by
Bubblewrap using ``--perms`` plus ``--ro-bind-data``.  No mutable runtime source
path is bind-mounted.

The only executable path and argv allowed inside the namespace are the fixed
probe path ``/usr/bin/busybox`` and ``sh -s``.  The executable bytes are bound
to the supplied snapshot, but this module has no independent trust pin proving
that they are BusyBox or harmless; the corresponding evidence flags therefore
remain false.  The sole snapshot payload may itself contain arbitrary program
bytes.  The API merely has no separate synthesized-candidate program, argv,
fixture, verifier, or score input.  The executable receives a hash-bound
constant shell program on standard input and reports bounded JSON about its own
projected payload.  Even successful evidence remains development-only and does
not establish the wider runtime-data/dlopen closure, a trusted supervisor,
seccomp policy, synthesized-candidate authorization, or claim eligibility.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import MISSING, dataclass, fields as dataclass_fields
import fcntl
from hashlib import sha256
import json
import math
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import secrets
import selectors
import signal
import stat
import subprocess
from time import monotonic
from typing import Final

from .development_runtime_bundle import canonical_development_runtime_json_bytes
from .development_runtime_fd_snapshot import (
    DevelopmentRuntimeFdSnapshot,
    DevelopmentRuntimeFdSnapshotError,
    verify_development_runtime_fd_snapshot_structure,
)


DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_SCHEMA_VERSION: Final[str] = "1.0.0"
DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_VERSION: Final[str] = "1.0.0"
DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_KIND: Final[str] = (
    "cbds-development-runtime-namespace-canary"
)
DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_ALGORITHM: Final[str] = (
    "systemd-openfile-bwrap-ro-bind-data-fixed-busybox-v1"
)
DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_PROBE_PATH: Final[str] = (
    "/usr/bin/busybox"
)
DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_UNIT_PREFIX: Final[str] = (
    "cbds-runtime-ns-canary-v1-"
)
DEVELOPMENT_RUNTIME_NAMESPACE_ACTIVATION_FD_START: Final[int] = 3
_MAXIMUM_REGULAR_BINDINGS: Final[int] = 512
_MAXIMUM_ARGV_BYTES: Final[int] = 512 * 1024
_HASH_CHUNK_BYTES: Final[int] = 1024 * 1024
_UNIT_RE: Final[re.Pattern[str]] = re.compile(
    r"cbds-runtime-ns-canary-v1-[0-9a-f]{32}\.service"
)
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")
_SAFE_PATH: Final[str] = (
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)
_RESERVED_PREFIXES: Final[tuple[str, ...]] = (
    "/dev",
    "/home",
    "/proc",
    "/sys",
    "/workspace",
)


class DevelopmentRuntimeNamespaceCanaryError(ValueError):
    """Raised when the fixed namespace canary cannot prove its boundary."""


@dataclass(frozen=True, slots=True)
class DevelopmentRuntimeNamespaceCanaryLimits:
    """Resource and capture ceilings for the fixed, candidate-free probe."""

    timeout_seconds: float = 10.0
    kill_grace_seconds: float = 1.0
    max_output_bytes: int = 64 * 1024
    memory_bytes: int = 64 * 1024 * 1024
    workspace_bytes: int = 16 * 1024 * 1024
    pids: int = 16
    open_files: int = 1024
    cpu_quota_percent: int = 100
    uid: int = 65534
    gid: int = 65534

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
        if self.kill_grace_seconds > self.timeout_seconds:
            raise ValueError("kill_grace_seconds cannot exceed timeout_seconds")
        minima = {
            "max_output_bytes": 1,
            "memory_bytes": 6 * 1024 * 1024,
            "workspace_bytes": 1024 * 1024,
            "pids": 2,
            "open_files": 32,
            "cpu_quota_percent": 1,
            "uid": 1,
            "gid": 1,
        }
        for name, minimum in minima.items():
            value = getattr(self, name)
            if type(value) is not int or value < minimum:
                raise ValueError(f"{name} must be an integer >= {minimum}")
        if self.cpu_quota_percent > 1000:
            raise ValueError("cpu_quota_percent must be <= 1000")
        if self.open_files > 1_048_576:
            raise ValueError("open_files exceeds the supported ceiling")
        if self.uid > 2**31 - 1 or self.gid > 2**31 - 1:
            raise ValueError("uid and gid exceed the supported range")

    def to_record(self) -> dict[str, int | float]:
        self.__post_init__()
        return {
            "timeout_seconds": float(self.timeout_seconds),
            "kill_grace_seconds": float(self.kill_grace_seconds),
            "max_output_bytes_per_stream": self.max_output_bytes,
            "memory_bytes": self.memory_bytes,
            "workspace_bytes": self.workspace_bytes,
            "pids": self.pids,
            "open_files": self.open_files,
            "cpu_quota_percent": self.cpu_quota_percent,
            "uid": self.uid,
            "gid": self.gid,
        }


@dataclass(frozen=True, slots=True)
class DevelopmentRuntimeNamespaceBinding:
    """Descriptor-free identity of one requested OpenFile/data bind."""

    ordinal: int
    service_fd: int
    slot_id: str
    destination_path: str
    mode: int
    size: int
    content_sha256: str

    def __post_init__(self) -> None:
        if type(self.ordinal) is not int or self.ordinal < 0:
            raise DevelopmentRuntimeNamespaceCanaryError("binding ordinal is invalid")
        if self.service_fd != DEVELOPMENT_RUNTIME_NAMESPACE_ACTIVATION_FD_START + self.ordinal:
            raise DevelopmentRuntimeNamespaceCanaryError("binding service_fd is invalid")
        if (
            type(self.slot_id) is not str
            or re.fullmatch(r"slot-[0-9a-f]{24}", self.slot_id) is None
        ):
            raise DevelopmentRuntimeNamespaceCanaryError("binding slot_id is invalid")
        _validate_runtime_path(self.destination_path)
        if type(self.mode) is not int or self.mode < 0 or self.mode & ~0o555:
            raise DevelopmentRuntimeNamespaceCanaryError("binding mode is invalid")
        if type(self.size) is not int or self.size < 0:
            raise DevelopmentRuntimeNamespaceCanaryError("binding size is invalid")
        _lower_sha256(self.content_sha256, what="binding content_sha256")

    def to_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "ordinal": self.ordinal,
            "service_fd": self.service_fd,
            "fd_name": self.slot_id,
            "destination_path": self.destination_path,
            "mode": self.mode,
            "size": self.size,
            "content_sha256": self.content_sha256,
        }


@dataclass(frozen=True, slots=True)
class DevelopmentRuntimeNamespaceCanaryResult:
    """Bounded host observation from exactly one fixed canary command."""

    returncode: int | None
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    output_truncated: bool = False
    launch_error: bool = False

    def __post_init__(self) -> None:
        if self.returncode is not None and type(self.returncode) is not int:
            raise TypeError("returncode must be an exact integer or None")
        if type(self.stdout) is not bytes or type(self.stderr) is not bytes:
            raise TypeError("stdout and stderr must be exact bytes")
        for name in ("timed_out", "output_truncated", "launch_error"):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be an exact boolean")


@dataclass(frozen=True, slots=True)
class _PinnedExecutable:
    path: str
    size: int
    sha256: str
    identity: tuple[int, ...]
    descriptor: int


_FIXED_PROBE_SOURCE: Final[str] = r'''set -eu
bb=/usr/bin/busybox
sha_line=$($bb sha256sum "$bb")
probe_sha256=${sha_line%% *}
probe_size=$($bb stat -c %s "$bb")
probe_chmod_blocked=1
if $bb sh -c '"$1" chmod 0755 "$1"' sh "$bb" 2>/dev/null; then
  probe_chmod_blocked=0
fi
probe_mode=$($bb stat -c %a "$bb")
probe_uid=$($bb stat -c %u "$bb")
probe_gid=$($bb stat -c %g "$bb")
probe_nlink=$($bb stat -c %h "$bb")
write_blocked=1
if $bb sh -c 'printf x >> "$1"' sh "$bb" 2>/dev/null; then
  write_blocked=0
fi
source_fd_leak_count=0
for fd_path in /proc/self/fd/*; do
  fd=${fd_path##*/}
  case "$fd" in
    *[!0-9]*|'') continue ;;
  esac
  if [ "$fd" -ge 3 ] && [ -r "$fd_path" ]; then
    source_fd_leak_count=$((source_fd_leak_count + 1))
  fi
done
root_writable=0
root_chmod_blocked=1
root_chmod_then_write_blocked=1
$bb sh -c 'if "$1" chmod 0755 /; then printf 0; else printf 1; fi' sh "$bb" > /workspace/.cbds-root-chmod-status 2>/dev/null || :
root_chmod_status=1
IFS= read -r root_chmod_status < /workspace/.cbds-root-chmod-status || :
$bb rm -f -- /workspace/.cbds-root-chmod-status
if [ "$root_chmod_status" = 0 ]; then
  root_chmod_blocked=0
fi
$bb sh -c 'if "$1" chmod 0755 / && : > /.cbds-root-write-probe; then printf 0; else printf 1; fi' sh "$bb" > /workspace/.cbds-root-attack-status 2>/dev/null || :
root_attack_status=1
IFS= read -r root_attack_status < /workspace/.cbds-root-attack-status || :
$bb rm -f -- /workspace/.cbds-root-attack-status
if [ "$root_attack_status" = 0 ]; then
  root_chmod_then_write_blocked=0
  root_writable=1
  $bb rm -f -- /.cbds-root-write-probe
fi
if $bb sh -c ': > "$1"' sh /.cbds-root-write-probe 2>/dev/null; then
  root_writable=1
  $bb rm -f -- /.cbds-root-write-probe
fi
workspace_writable=0
if $bb sh -c ': > "$1"' sh /workspace/.cbds-workspace-probe 2>/dev/null; then
  workspace_writable=1
  $bb rm -f -- /workspace/.cbds-workspace-probe
fi
non_loopback_interfaces=0
{
  IFS= read -r _ || :
  IFS= read -r _ || :
  while IFS=: read -r interface _; do
    interface=${interface//[[:space:]]/}
    [ "$interface" = lo ] || non_loopback_interfaces=$((non_loopback_interfaces + 1))
  done
} < /proc/net/dev
host_home_visible=0
[ ! -e /home ] || host_home_visible=1
host_sys_visible=0
[ ! -e /sys ] || host_sys_visible=1
$bb printf '{"schema_version":"1.0.0","probe_sha256":"%s","probe_size":%s,"probe_mode":"%s","probe_uid":%s,"probe_gid":%s,"probe_nlink":%s,"probe_chmod_blocked":%s,"write_blocked":%s,"source_fd_leak_count":%s,"root_chmod_blocked":%s,"root_chmod_then_write_blocked":%s,"root_writable":%s,"workspace_writable":%s,"non_loopback_interfaces":%s,"host_home_visible":%s,"host_sys_visible":%s}\n' "$probe_sha256" "$probe_size" "$probe_mode" "$probe_uid" "$probe_gid" "$probe_nlink" "$probe_chmod_blocked" "$write_blocked" "$source_fd_leak_count" "$root_chmod_blocked" "$root_chmod_then_write_blocked" "$root_writable" "$workspace_writable" "$non_loopback_interfaces" "$host_home_visible" "$host_sys_visible"
'''
DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_PROBE_SHA256: Final[str] = sha256(
    _FIXED_PROBE_SOURCE.encode("utf-8")
).hexdigest()


NamespaceCanaryRunner = Callable[..., DevelopmentRuntimeNamespaceCanaryResult]


def _lower_sha256(value: object, *, what: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise DevelopmentRuntimeNamespaceCanaryError(
            f"{what} must be lowercase SHA-256"
        )
    return value


def _validate_runtime_path(value: object, *, allow_root: bool = False) -> str:
    if type(value) is not str:
        raise DevelopmentRuntimeNamespaceCanaryError("runtime path is not text")
    path = PurePosixPath(value)
    if (
        not value.startswith("/")
        or value.startswith("//")
        or str(path) != value
        or any(character in value for character in ("\x00", "\r", "\n"))
        or "." in path.parts
        or ".." in path.parts
        or (value == "/" and not allow_root)
    ):
        raise DevelopmentRuntimeNamespaceCanaryError(
            "runtime path must be normalized and absolute"
        )
    return value


def _validate_executable_path(value: object, *, what: str) -> str:
    path = _validate_runtime_path(value)
    if path.startswith("/proc/"):
        raise DevelopmentRuntimeNamespaceCanaryError(
            f"{what} cannot be supplied through procfs"
        )
    return path


def _is_reserved(path: str) -> bool:
    return any(path == prefix or path.startswith(prefix + "/") for prefix in _RESERVED_PREFIXES)


def _seconds_text(value: float) -> str:
    return f"{value:.6f}".rstrip("0").rstrip(".") + "s"


def _binding_index(snapshot: DevelopmentRuntimeFdSnapshot) -> tuple[DevelopmentRuntimeNamespaceBinding, ...]:
    return tuple(
        DevelopmentRuntimeNamespaceBinding(
            ordinal=index,
            service_fd=DEVELOPMENT_RUNTIME_NAMESPACE_ACTIVATION_FD_START + index,
            slot_id=slot.slot_id,
            destination_path=slot.destination_path,
            mode=slot.materialized_mode,
            size=slot.size,
            content_sha256=slot.content_sha256,
        )
        for index, slot in enumerate(snapshot.regular_slots)
    )


def _validate_snapshot_for_canary(
    snapshot: object,
    limits: DevelopmentRuntimeNamespaceCanaryLimits,
) -> tuple[DevelopmentRuntimeNamespaceBinding, ...]:
    if type(snapshot) is not DevelopmentRuntimeFdSnapshot:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "snapshot must be an exact DevelopmentRuntimeFdSnapshot"
        )
    if not verify_development_runtime_fd_snapshot_structure(snapshot):
        raise DevelopmentRuntimeNamespaceCanaryError("snapshot structure is invalid")
    if snapshot.closed:
        raise DevelopmentRuntimeNamespaceCanaryError("snapshot is already closed")
    if snapshot.regular_file_count != 1:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "fixed canary snapshot must contain exactly one regular payload"
        )
    if DEVELOPMENT_RUNTIME_NAMESPACE_ACTIVATION_FD_START + snapshot.regular_file_count + 16 > limits.open_files:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "open_files cannot accommodate activation descriptors"
        )
    all_paths = [item.destination_path for item in snapshot.directories]
    all_paths.extend(item.destination_path for item in snapshot.entries)
    if any(_is_reserved(path) for path in all_paths):
        raise DevelopmentRuntimeNamespaceCanaryError(
            "snapshot conflicts with a reserved namespace path"
        )
    if tuple(item.destination_path for item in snapshot.directories) != (
        "/",
        "/usr",
        "/usr/bin",
    ):
        raise DevelopmentRuntimeNamespaceCanaryError(
            "fixed canary snapshot directory inventory is not exact"
        )
    if (
        len(snapshot.entries) != 1
        or snapshot.symlink_count != 0
        or snapshot.entries[0].destination_path
        != DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_PROBE_PATH
        or snapshot.entries[0].kind != "regular"
        or not snapshot.entries[0].mode & 0o111
    ):
        raise DevelopmentRuntimeNamespaceCanaryError(
            "fixed canary snapshot payload inventory is not exact"
        )
    return _binding_index(snapshot)


def _validate_unit_name(value: object) -> str:
    if type(value) is not str or _UNIT_RE.fullmatch(value) is None:
        raise DevelopmentRuntimeNamespaceCanaryError("canary unit name is invalid")
    return value


def _argv_size(argv: tuple[str, ...]) -> int:
    return sum(len(item.encode("utf-8")) + 1 for item in argv)


def _build_launch_argv_from_bindings(
    bindings: tuple[DevelopmentRuntimeNamespaceBinding, ...],
    *,
    systemd_run: str,
    unit_name: str,
    limits: DevelopmentRuntimeNamespaceCanaryLimits,
    openfile_sources: tuple[str, ...],
    bwrap_executable: str,
) -> tuple[str, ...]:
    """Build one complete argv from validated, descriptor-shaped inputs.

    This is shared by the live builder and evidence verifier.  The latter uses
    stable placeholders for controller-owned descriptors, so every property,
    namespace option, environment setting, mount, mode, and command token is
    compared against one deterministic contract rather than a partial list.
    """

    if len(openfile_sources) != len(bindings):
        raise DevelopmentRuntimeNamespaceCanaryError(
            "OpenFile source inventory differs from its bindings"
        )
    runtime_max = _seconds_text(
        float(limits.timeout_seconds) + float(limits.kill_grace_seconds)
    )
    properties = (
        f"MemoryMax={limits.memory_bytes}",
        "MemorySwapMax=0",
        f"TasksMax={limits.pids}",
        f"CPUQuota={limits.cpu_quota_percent}%",
        f"LimitNOFILE={limits.open_files}",
        "LimitCORE=0",
        f"RuntimeMaxSec={runtime_max}",
        f"TimeoutStopSec={_seconds_text(float(limits.kill_grace_seconds))}",
        "KillMode=control-group",
        "SendSIGKILL=yes",
        "OOMPolicy=kill",
        "NoNewPrivileges=yes",
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
        "--expand-environment=no",
        f"--unit={unit_name}",
    ]
    for item in properties:
        argv.extend(("--property", item))
    for binding, source in zip(bindings, openfile_sources, strict=True):
        argv.extend(
            (
                "--property",
                f"OpenFile={source}:{binding.slot_id}:read-only",
            )
        )
    argv.extend(
        (
            bwrap_executable,
            "--unshare-all",
            "--unshare-user",
            "--uid",
            str(limits.uid),
            "--gid",
            str(limits.gid),
            "--disable-userns",
            "--assert-userns-disabled",
            "--die-with-parent",
            "--new-session",
            "--as-pid-1",
            "--clearenv",
            "--dir",
            "/usr",
            "--dir",
            "/usr/bin",
        )
    )
    for binding in bindings:
        argv.extend(
            (
                "--perms",
                f"{binding.mode:04o}",
                "--ro-bind-data",
                str(binding.service_fd),
                binding.destination_path,
            )
        )
    argv.extend(
        (
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--size",
            str(limits.workspace_bytes),
            "--tmpfs",
            "/workspace",
            "--dir",
            "/workspace/tmp",
            "--chmod",
            "0700",
            "/workspace",
            "--chmod",
            "0555",
            "/usr/bin",
            "--chmod",
            "0555",
            "/usr",
            "--setenv",
            "HOME",
            "/workspace",
            "--setenv",
            "TMPDIR",
            "/workspace/tmp",
            "--setenv",
            "PATH",
            "/usr/bin",
            "--setenv",
            "LANG",
            "C",
            "--setenv",
            "LC_ALL",
            "C",
            "--setenv",
            "TZ",
            "UTC",
            "--chmod",
            "0555",
            "/",
            "--remount-ro",
            "/",
            "--chdir",
            "/workspace",
            DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_PROBE_PATH,
            "sh",
            "-s",
        )
    )
    result = tuple(argv)
    if _argv_size(result) > _MAXIMUM_ARGV_BYTES:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "canary argv exceeds its byte bound"
        )
    return result


def build_development_runtime_namespace_canary_argv(
    snapshot: DevelopmentRuntimeFdSnapshot,
    *,
    controller_pid: int,
    controller_regular_fds: tuple[int, ...],
    bwrap_controller_fd: int,
    systemd_run: str = "/usr/bin/systemd-run",
    unit_name: str,
    limits: DevelopmentRuntimeNamespaceCanaryLimits | None = None,
) -> tuple[str, ...]:
    """Build the exact fixed canary argv; it never accepts a command or payload."""

    selected = limits if limits is not None else DevelopmentRuntimeNamespaceCanaryLimits()
    if type(selected) is not DevelopmentRuntimeNamespaceCanaryLimits:
        raise TypeError("limits must be exact DevelopmentRuntimeNamespaceCanaryLimits")
    selected.__post_init__()
    bindings = _validate_snapshot_for_canary(snapshot, selected)
    if type(controller_pid) is not int or controller_pid <= 1:
        raise DevelopmentRuntimeNamespaceCanaryError("controller_pid is invalid")
    if (
        type(controller_regular_fds) is not tuple
        or len(controller_regular_fds) != len(bindings)
        or any(type(item) is not int or item < 3 for item in controller_regular_fds)
        or len(set(controller_regular_fds)) != len(controller_regular_fds)
    ):
        raise DevelopmentRuntimeNamespaceCanaryError(
            "controller regular descriptor table is invalid"
        )
    if type(bwrap_controller_fd) is not int or bwrap_controller_fd < 3:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "Bubblewrap controller descriptor is invalid"
        )
    if bwrap_controller_fd in controller_regular_fds:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "Bubblewrap descriptor aliases a runtime descriptor"
        )
    _validate_executable_path(systemd_run, what="systemd_run")
    _validate_unit_name(unit_name)

    return _build_launch_argv_from_bindings(
        bindings,
        systemd_run=systemd_run,
        unit_name=unit_name,
        limits=selected,
        openfile_sources=tuple(
            f"/proc/{controller_pid}/fd/{descriptor}"
            for descriptor in controller_regular_fds
        ),
        bwrap_executable=f"/proc/{controller_pid}/fd/{bwrap_controller_fd}",
    )


def _normalized_launch_contract(
    argv: tuple[str, ...],
    bindings: tuple[DevelopmentRuntimeNamespaceBinding, ...],
) -> tuple[str, ...]:
    if type(argv) is not tuple or any(type(item) is not str for item in argv):
        raise DevelopmentRuntimeNamespaceCanaryError("launch argv is not exact text")
    try:
        bwrap_index = argv.index("--unshare-all") - 1
    except ValueError as exc:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "launch argv omits Bubblewrap namespace setup"
        ) from exc
    result = list(argv)
    if bwrap_index < 1:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "launch argv Bubblewrap descriptor path is invalid"
        )
    descriptor_path = re.fullmatch(
        r"/proc/([1-9][0-9]*)/fd/([0-9]+)",
        result[bwrap_index],
    )
    if descriptor_path is None or int(descriptor_path.group(2)) < 3:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "launch argv Bubblewrap descriptor path is invalid"
        )
    controller_pid = descriptor_path.group(1)
    result[bwrap_index] = "@controller-bwrap-fd"
    found: list[str] = []
    pattern = re.compile(
        r"OpenFile=/proc/([1-9][0-9]*)/fd/([0-9]+):"
        r"(slot-[0-9a-f]{24}):read-only"
    )
    for index, item in enumerate(result):
        match = pattern.fullmatch(item)
        if match is None:
            continue
        if match.group(1) != controller_pid or int(match.group(2)) < 3:
            raise DevelopmentRuntimeNamespaceCanaryError(
                "launch argv OpenFile descriptor path is invalid"
            )
        slot_id = match.group(3)
        found.append(slot_id)
        result[index] = f"OpenFile=@controller-runtime-fd:{slot_id}:read-only"
    if found != [item.slot_id for item in bindings]:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "launch argv OpenFile order differs from its bindings"
        )
    if any(re.search(r"/proc/[1-9][0-9]*/fd/[0-9]+", item) for item in result):
        raise DevelopmentRuntimeNamespaceCanaryError(
            "launch contract retained a raw controller descriptor"
        )
    return tuple(result)


def _validate_launch_contract(
    evidence: "DevelopmentRuntimeNamespaceCanaryEvidence",
) -> None:
    if type(evidence.limits) is not DevelopmentRuntimeNamespaceCanaryLimits:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "evidence limits are not an exact typed policy"
        )
    evidence.limits.__post_init__()
    argv = evidence.launch_contract_argv
    if (
        type(argv) is not tuple
        or not argv
        or any(type(item) is not str for item in argv)
        or _argv_size(argv) > _MAXIMUM_ARGV_BYTES
    ):
        raise DevelopmentRuntimeNamespaceCanaryError(
            "evidence launch contract argv is invalid"
        )
    if sha256(canonical_development_runtime_json_bytes(list(argv))).hexdigest() != evidence.launch_contract_sha256:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "evidence launch contract digest is invalid"
        )
    expected = _build_launch_argv_from_bindings(
        evidence.bindings,
        systemd_run=evidence.systemd_run_path,
        unit_name=evidence.unit_name,
        limits=evidence.limits,
        openfile_sources=tuple(
            "@controller-runtime-fd" for _binding in evidence.bindings
        ),
        bwrap_executable="@controller-bwrap-fd",
    )
    if argv != expected:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "evidence launch contract differs from the exact fixed template"
        )


def _resolve_probe_binding(
    snapshot: DevelopmentRuntimeFdSnapshot,
    bindings: tuple[DevelopmentRuntimeNamespaceBinding, ...],
) -> DevelopmentRuntimeNamespaceBinding:
    del snapshot
    if (
        len(bindings) != 1
        or bindings[0].destination_path
        != DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_PROBE_PATH
    ):
        raise DevelopmentRuntimeNamespaceCanaryError(
            "fixed probe binding inventory is invalid"
        )
    return bindings[0]


def _binding_index_sha256(
    bindings: tuple[DevelopmentRuntimeNamespaceBinding, ...],
) -> str:
    return sha256(
        canonical_development_runtime_json_bytes(
            [item.to_record() for item in bindings]
        )
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class DevelopmentRuntimeNamespaceCanaryEvidence:
    """Descriptor-free evidence from one successful fixed probe evaluation."""

    source_snapshot_sha256: str
    source_projection_sha256: str
    bindings: tuple[DevelopmentRuntimeNamespaceBinding, ...]
    binding_index_sha256: str
    unit_name: str
    limits: DevelopmentRuntimeNamespaceCanaryLimits
    argv_sha256: str
    launch_contract_argv: tuple[str, ...]
    launch_contract_sha256: str
    systemd_run_path: str
    systemd_run_sha256: str
    bwrap_path: str
    bwrap_sha256: str
    systemctl_path: str
    systemctl_sha256: str
    probe_source_sha256: str
    probe_regular_path: str
    expected_probe_sha256: str
    expected_probe_size: int
    expected_probe_mode: int
    namespace_uid: int
    namespace_gid: int
    reported_probe_sha256: str
    reported_probe_size: int
    reported_probe_mode: int
    reported_probe_uid: int
    reported_probe_gid: int
    reported_probe_nlink: int
    reported_probe_chmod_blocked: int
    reported_payload_write_blocked: int
    reported_persistent_fd_count_at_or_above_three: int
    reported_root_chmod_blocked: int
    reported_root_chmod_then_write_blocked: int
    reported_root_writable: int
    reported_workspace_writable: int
    reported_non_loopback_interfaces: int
    reported_host_home_visible: int
    reported_host_sys_visible: int
    stdout_bytes: int
    stdout_sha256: str
    stderr_bytes: int
    stderr_sha256: str
    runner_injected: bool
    default_runner_invoked: bool
    evidence_sha256: str
    schema_version: str = DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_SCHEMA_VERSION
    canary_version: str = DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_VERSION
    kind: str = DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_KIND
    algorithm: str = DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_ALGORITHM
    systemd_openfile_projection_requested: bool = True
    bwrap_ro_bind_data_projection_requested: bool = True
    bwrap_ro_bind_fd_used: bool = False
    mutable_host_runtime_bind_used: bool = False
    fixed_probe_request_validated: bool = True
    bounded_probe_observation_validated: bool = True
    synthesized_candidate_input_api_absent: bool = True
    only_fixed_probe_payload_present: bool = True
    payload_write_blocked_verified: bool = False
    probe_chmod_blocked_verified: bool = False
    activation_fds_closed_verified: bool = False
    root_chmod_blocked_verified: bool = False
    root_read_only_verified: bool = False
    workspace_writable_verified: bool = False
    no_non_loopback_interfaces_verified: bool = False
    host_home_absent_verified: bool = False
    host_sys_absent_verified: bool = False
    systemd_openfile_handoff_verified: bool = False
    bubblewrap_ro_bind_data_handoff_verified: bool = False
    projected_probe_payload_verified: bool = False
    projected_probe_mode_verified: bool = False
    fixed_probe_executed: bool = False
    externally_trusted_launcher: bool = False
    externally_trusted_probe_executable: bool = False
    harmless_probe_executed: bool = False
    runtime_data_and_dlopen_closure_verified: bool = False
    namespace_runtime_closure_verified: bool = False
    trusted_pid1_supervisor_implemented: bool = False
    child_seccomp_filter_implemented: bool = False
    launch_eligible: bool = False
    # These two fields refer only to the absent synthesized-candidate input
    # path, not to the untrusted program bytes carried by the sole snapshot
    # payload.
    candidate_execution_authorized: bool = False
    candidate_executed: bool = False
    scored_evaluation_eligible: bool = False
    claim_pipeline_eligible: bool = False

    def __post_init__(self) -> None:
        _validate_evidence(self)

    def to_record(self) -> dict[str, object]:
        _validate_evidence(self)
        return _evidence_record(self, include_self_digest=True)


def _evidence_record(
    evidence: DevelopmentRuntimeNamespaceCanaryEvidence,
    *,
    include_self_digest: bool,
) -> dict[str, object]:
    record: dict[str, object] = {
        "schema_version": evidence.schema_version,
        "canary_version": evidence.canary_version,
        "kind": evidence.kind,
        "algorithm": evidence.algorithm,
        "source_snapshot_sha256": evidence.source_snapshot_sha256,
        "source_projection_sha256": evidence.source_projection_sha256,
        "bindings": [item.to_record() for item in evidence.bindings],
        "binding_index_sha256": evidence.binding_index_sha256,
        "unit_name": evidence.unit_name,
        "limits": evidence.limits.to_record(),
        "argv_sha256": evidence.argv_sha256,
        "launch_contract_argv": list(evidence.launch_contract_argv),
        "launch_contract_sha256": evidence.launch_contract_sha256,
        "systemd_run_path": evidence.systemd_run_path,
        "systemd_run_sha256": evidence.systemd_run_sha256,
        "bwrap_path": evidence.bwrap_path,
        "bwrap_sha256": evidence.bwrap_sha256,
        "systemctl_path": evidence.systemctl_path,
        "systemctl_sha256": evidence.systemctl_sha256,
        "probe_source_sha256": evidence.probe_source_sha256,
        "probe_regular_path": evidence.probe_regular_path,
        "expected_probe_sha256": evidence.expected_probe_sha256,
        "expected_probe_size": evidence.expected_probe_size,
        "expected_probe_mode": evidence.expected_probe_mode,
        "namespace_uid": evidence.namespace_uid,
        "namespace_gid": evidence.namespace_gid,
        "reported_probe_sha256": evidence.reported_probe_sha256,
        "reported_probe_size": evidence.reported_probe_size,
        "reported_probe_mode": evidence.reported_probe_mode,
        "reported_probe_uid": evidence.reported_probe_uid,
        "reported_probe_gid": evidence.reported_probe_gid,
        "reported_probe_nlink": evidence.reported_probe_nlink,
        "reported_probe_chmod_blocked": evidence.reported_probe_chmod_blocked,
        "reported_payload_write_blocked": evidence.reported_payload_write_blocked,
        "reported_persistent_fd_count_at_or_above_three": evidence.reported_persistent_fd_count_at_or_above_three,
        "reported_root_chmod_blocked": evidence.reported_root_chmod_blocked,
        "reported_root_chmod_then_write_blocked": evidence.reported_root_chmod_then_write_blocked,
        "reported_root_writable": evidence.reported_root_writable,
        "reported_workspace_writable": evidence.reported_workspace_writable,
        "reported_non_loopback_interfaces": evidence.reported_non_loopback_interfaces,
        "reported_host_home_visible": evidence.reported_host_home_visible,
        "reported_host_sys_visible": evidence.reported_host_sys_visible,
        "stdout_bytes": evidence.stdout_bytes,
        "stdout_sha256": evidence.stdout_sha256,
        "stderr_bytes": evidence.stderr_bytes,
        "stderr_sha256": evidence.stderr_sha256,
        "runner_injected": evidence.runner_injected,
        "default_runner_invoked": evidence.default_runner_invoked,
        "systemd_openfile_projection_requested": evidence.systemd_openfile_projection_requested,
        "bwrap_ro_bind_data_projection_requested": evidence.bwrap_ro_bind_data_projection_requested,
        "bwrap_ro_bind_fd_used": evidence.bwrap_ro_bind_fd_used,
        "mutable_host_runtime_bind_used": evidence.mutable_host_runtime_bind_used,
        "fixed_probe_request_validated": evidence.fixed_probe_request_validated,
        "bounded_probe_observation_validated": evidence.bounded_probe_observation_validated,
        "synthesized_candidate_input_api_absent": evidence.synthesized_candidate_input_api_absent,
        "only_fixed_probe_payload_present": evidence.only_fixed_probe_payload_present,
        "payload_write_blocked_verified": evidence.payload_write_blocked_verified,
        "probe_chmod_blocked_verified": evidence.probe_chmod_blocked_verified,
        "activation_fds_closed_verified": evidence.activation_fds_closed_verified,
        "root_chmod_blocked_verified": evidence.root_chmod_blocked_verified,
        "root_read_only_verified": evidence.root_read_only_verified,
        "workspace_writable_verified": evidence.workspace_writable_verified,
        "no_non_loopback_interfaces_verified": evidence.no_non_loopback_interfaces_verified,
        "host_home_absent_verified": evidence.host_home_absent_verified,
        "host_sys_absent_verified": evidence.host_sys_absent_verified,
        "systemd_openfile_handoff_verified": evidence.systemd_openfile_handoff_verified,
        "bubblewrap_ro_bind_data_handoff_verified": evidence.bubblewrap_ro_bind_data_handoff_verified,
        "projected_probe_payload_verified": evidence.projected_probe_payload_verified,
        "projected_probe_mode_verified": evidence.projected_probe_mode_verified,
        "fixed_probe_executed": evidence.fixed_probe_executed,
        "externally_trusted_launcher": evidence.externally_trusted_launcher,
        "externally_trusted_probe_executable": evidence.externally_trusted_probe_executable,
        "harmless_probe_executed": evidence.harmless_probe_executed,
        "runtime_data_and_dlopen_closure_verified": evidence.runtime_data_and_dlopen_closure_verified,
        "namespace_runtime_closure_verified": evidence.namespace_runtime_closure_verified,
        "trusted_pid1_supervisor_implemented": evidence.trusted_pid1_supervisor_implemented,
        "child_seccomp_filter_implemented": evidence.child_seccomp_filter_implemented,
        "launch_eligible": evidence.launch_eligible,
        "candidate_execution_authorized": evidence.candidate_execution_authorized,
        "candidate_executed": evidence.candidate_executed,
        "scored_evaluation_eligible": evidence.scored_evaluation_eligible,
        "claim_pipeline_eligible": evidence.claim_pipeline_eligible,
    }
    if include_self_digest:
        record["evidence_sha256"] = evidence.evidence_sha256
    return record


def _compute_evidence_sha256(
    evidence: DevelopmentRuntimeNamespaceCanaryEvidence,
) -> str:
    return sha256(
        canonical_development_runtime_json_bytes(
            _evidence_record(evidence, include_self_digest=False)
        )
    ).hexdigest()


def _validate_evidence(evidence: DevelopmentRuntimeNamespaceCanaryEvidence) -> None:
    exact: dict[str, object] = {
        "schema_version": DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_SCHEMA_VERSION,
        "canary_version": DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_VERSION,
        "kind": DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_KIND,
        "algorithm": DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_ALGORITHM,
        "systemd_openfile_projection_requested": True,
        "bwrap_ro_bind_data_projection_requested": True,
        "bwrap_ro_bind_fd_used": False,
        "mutable_host_runtime_bind_used": False,
        "fixed_probe_request_validated": True,
        "bounded_probe_observation_validated": True,
        "synthesized_candidate_input_api_absent": True,
        "only_fixed_probe_payload_present": True,
        "payload_write_blocked_verified": False,
        "probe_chmod_blocked_verified": False,
        "activation_fds_closed_verified": False,
        "root_chmod_blocked_verified": False,
        "root_read_only_verified": False,
        "workspace_writable_verified": False,
        "no_non_loopback_interfaces_verified": False,
        "host_home_absent_verified": False,
        "host_sys_absent_verified": False,
        "systemd_openfile_handoff_verified": False,
        "bubblewrap_ro_bind_data_handoff_verified": False,
        "projected_probe_payload_verified": False,
        "projected_probe_mode_verified": False,
        "fixed_probe_executed": False,
        "externally_trusted_launcher": False,
        "externally_trusted_probe_executable": False,
        "harmless_probe_executed": False,
        "runtime_data_and_dlopen_closure_verified": False,
        "namespace_runtime_closure_verified": False,
        "trusted_pid1_supervisor_implemented": False,
        "child_seccomp_filter_implemented": False,
        "launch_eligible": False,
        "candidate_execution_authorized": False,
        "candidate_executed": False,
        "scored_evaluation_eligible": False,
        "claim_pipeline_eligible": False,
    }
    for name, expected in exact.items():
        actual = getattr(evidence, name)
        if type(actual) is not type(expected) or actual != expected:
            raise DevelopmentRuntimeNamespaceCanaryError(
                f"evidence field {name!r} is invalid"
            )
    if type(evidence.runner_injected) is not bool:
        raise DevelopmentRuntimeNamespaceCanaryError("runner_injected is invalid")
    if (
        type(evidence.default_runner_invoked) is not bool
        or evidence.default_runner_invoked is evidence.runner_injected
    ):
        raise DevelopmentRuntimeNamespaceCanaryError(
            "runner provenance fields are inconsistent"
        )
    for name in (
        "source_snapshot_sha256",
        "source_projection_sha256",
        "binding_index_sha256",
        "argv_sha256",
        "launch_contract_sha256",
        "systemd_run_sha256",
        "bwrap_sha256",
        "systemctl_sha256",
        "probe_source_sha256",
        "expected_probe_sha256",
        "reported_probe_sha256",
        "stdout_sha256",
        "stderr_sha256",
        "evidence_sha256",
    ):
        _lower_sha256(getattr(evidence, name), what=name)
    if evidence.probe_source_sha256 != DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_PROBE_SHA256:
        raise DevelopmentRuntimeNamespaceCanaryError("probe source digest is invalid")
    if (
        type(evidence.bindings) is not tuple
        or len(evidence.bindings) != 1
        or any(
            type(item) is not DevelopmentRuntimeNamespaceBinding
            for item in evidence.bindings
        )
        or evidence.bindings[0].destination_path
        != DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_PROBE_PATH
    ):
        raise DevelopmentRuntimeNamespaceCanaryError("evidence bindings are invalid")
    for index, item in enumerate(evidence.bindings):
        item.__post_init__()
        if item.ordinal != index:
            raise DevelopmentRuntimeNamespaceCanaryError(
                "evidence binding order is invalid"
            )
    if evidence.binding_index_sha256 != _binding_index_sha256(evidence.bindings):
        raise DevelopmentRuntimeNamespaceCanaryError(
            "evidence binding index digest is invalid"
        )
    _validate_unit_name(evidence.unit_name)
    for name in ("systemd_run_path", "bwrap_path", "systemctl_path"):
        _validate_executable_path(getattr(evidence, name), what=name)
    _validate_runtime_path(evidence.probe_regular_path)
    integers = (
        "expected_probe_size",
        "expected_probe_mode",
        "namespace_uid",
        "namespace_gid",
        "reported_probe_size",
        "reported_probe_mode",
        "reported_probe_uid",
        "reported_probe_gid",
        "reported_probe_nlink",
        "reported_probe_chmod_blocked",
        "reported_payload_write_blocked",
        "reported_persistent_fd_count_at_or_above_three",
        "reported_root_chmod_blocked",
        "reported_root_chmod_then_write_blocked",
        "reported_root_writable",
        "reported_workspace_writable",
        "reported_non_loopback_interfaces",
        "reported_host_home_visible",
        "reported_host_sys_visible",
        "stdout_bytes",
        "stderr_bytes",
    )
    for name in integers:
        value = getattr(evidence, name)
        if type(value) is not int or value < 0:
            raise DevelopmentRuntimeNamespaceCanaryError(
                f"evidence integer {name!r} is invalid"
            )
    if (
        evidence.expected_probe_sha256 != evidence.reported_probe_sha256
        or evidence.expected_probe_size != evidence.reported_probe_size
        or evidence.expected_probe_mode != evidence.reported_probe_mode
        or evidence.namespace_uid != evidence.reported_probe_uid
        or evidence.namespace_gid != evidence.reported_probe_gid
        or evidence.reported_probe_nlink != 0
    ):
        raise DevelopmentRuntimeNamespaceCanaryError(
            "reported probe metadata differs from the requested projection"
        )
    if (
        evidence.namespace_uid != evidence.limits.uid
        or evidence.namespace_gid != evidence.limits.gid
    ):
        raise DevelopmentRuntimeNamespaceCanaryError(
            "reported namespace identity differs from the launch policy"
        )
    reported_security = {
        "reported_probe_chmod_blocked": 1,
        "reported_payload_write_blocked": 1,
        "reported_persistent_fd_count_at_or_above_three": 0,
        "reported_root_chmod_blocked": 1,
        "reported_root_chmod_then_write_blocked": 1,
        "reported_root_writable": 0,
        "reported_workspace_writable": 1,
        "reported_non_loopback_interfaces": 0,
        "reported_host_home_visible": 0,
        "reported_host_sys_visible": 0,
    }
    for name, expected in reported_security.items():
        if getattr(evidence, name) != expected:
            raise DevelopmentRuntimeNamespaceCanaryError(
                "reported probe security fields are invalid"
            )
    matching = [
        item for item in evidence.bindings
        if item.destination_path == evidence.probe_regular_path
    ]
    if len(matching) != 1:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "probe regular path does not bind exactly one slot"
        )
    binding = matching[0]
    if (
        binding.content_sha256 != evidence.expected_probe_sha256
        or binding.size != evidence.expected_probe_size
        or binding.mode != evidence.expected_probe_mode
    ):
        raise DevelopmentRuntimeNamespaceCanaryError(
            "probe expectations differ from their binding"
        )
    expected_stdout = _expected_probe_output_bytes(
        digest=evidence.reported_probe_sha256,
        size=evidence.reported_probe_size,
        mode=evidence.reported_probe_mode,
        uid=evidence.reported_probe_uid,
        gid=evidence.reported_probe_gid,
        nlink=evidence.reported_probe_nlink,
    )
    if (
        evidence.stdout_bytes != len(expected_stdout)
        or evidence.stdout_sha256 != sha256(expected_stdout).hexdigest()
        or evidence.stderr_bytes != 0
        or evidence.stderr_sha256 != sha256(b"").hexdigest()
    ):
        raise DevelopmentRuntimeNamespaceCanaryError(
            "evidence output identity is invalid"
        )
    _validate_launch_contract(evidence)
    if evidence.evidence_sha256 != _compute_evidence_sha256(evidence):
        raise DevelopmentRuntimeNamespaceCanaryError("evidence digest is invalid")


def verify_development_runtime_namespace_canary_evidence(value: object) -> bool:
    """Return whether an exact typed evidence object is structurally valid."""

    if type(value) is not DevelopmentRuntimeNamespaceCanaryEvidence:
        return False
    try:
        _validate_evidence(value)
    except (
        AttributeError,
        DevelopmentRuntimeNamespaceCanaryError,
        OSError,
        TypeError,
        ValueError,
    ):
        return False
    return True


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _hash_descriptor(descriptor: int, size: int) -> str:
    digest = sha256()
    offset = 0
    while offset < size:
        block = os.pread(descriptor, min(_HASH_CHUNK_BYTES, size - offset), offset)
        if not block:
            raise DevelopmentRuntimeNamespaceCanaryError(
                "descriptor ended before its authenticated size"
            )
        digest.update(block)
        offset += len(block)
    if os.pread(descriptor, 1, size):
        raise DevelopmentRuntimeNamespaceCanaryError(
            "descriptor grew beyond its authenticated size"
        )
    return digest.hexdigest()


def _open_pinned_executable(path_text: str, *, what: str) -> _PinnedExecutable:
    _validate_executable_path(path_text, what=what)
    try:
        resolved = os.path.realpath(path_text, strict=True)
    except OSError as exc:
        raise DevelopmentRuntimeNamespaceCanaryError(
            f"{what} cannot be resolved"
        ) from exc
    _validate_executable_path(resolved, what=what)
    flags = os.O_RDONLY | os.O_CLOEXEC
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if type(nofollow) is not int or nofollow <= 0:
        raise DevelopmentRuntimeNamespaceCanaryError("O_NOFOLLOW is unavailable")
    descriptor: int | None = None
    try:
        descriptor = os.open(resolved, flags | nofollow)
        metadata = os.fstat(descriptor)
        named = os.stat(resolved, follow_symlinks=False)
        identity = _metadata_identity(metadata)
        if (
            identity != _metadata_identity(named)
            or not stat.S_ISREG(metadata.st_mode)
            or not metadata.st_mode & 0o111
            or metadata.st_size <= 0
            or metadata.st_size > 512 * 1024 * 1024
            or os.get_inheritable(descriptor)
        ):
            raise DevelopmentRuntimeNamespaceCanaryError(
                f"{what} is not a pinned bounded executable"
            )
        digest = _hash_descriptor(descriptor, metadata.st_size)
        result = _PinnedExecutable(
            path=resolved,
            size=metadata.st_size,
            sha256=digest,
            identity=identity,
            descriptor=descriptor,
        )
        descriptor = None
        return result
    except DevelopmentRuntimeNamespaceCanaryError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise DevelopmentRuntimeNamespaceCanaryError(
            f"{what} pinning failed closed"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _verify_pinned_executable(value: _PinnedExecutable, *, what: str) -> None:
    try:
        opened = os.fstat(value.descriptor)
        named = os.stat(value.path, follow_symlinks=False)
    except OSError as exc:
        raise DevelopmentRuntimeNamespaceCanaryError(
            f"{what} disappeared during the canary"
        ) from exc
    if (
        _metadata_identity(opened) != value.identity
        or _metadata_identity(named) != value.identity
        or os.get_inheritable(value.descriptor)
        or _hash_descriptor(value.descriptor, value.size) != value.sha256
    ):
        raise DevelopmentRuntimeNamespaceCanaryError(
            f"{what} changed during the canary"
        )


def _required_seals() -> int:
    values: list[int] = []
    for name in ("F_SEAL_SEAL", "F_SEAL_SHRINK", "F_SEAL_GROW", "F_SEAL_WRITE"):
        value = getattr(fcntl, name, None)
        if type(value) is not int or value < 0:
            raise DevelopmentRuntimeNamespaceCanaryError(
                f"required seal primitive {name} is unavailable"
            )
        values.append(value)
    return values[0] | values[1] | values[2] | values[3]


def _verify_controller_regular_fd(
    descriptor: int,
    binding: DevelopmentRuntimeNamespaceBinding,
) -> None:
    get_seals = getattr(fcntl, "F_GET_SEALS", None)
    if type(get_seals) is not int or get_seals < 0:
        raise DevelopmentRuntimeNamespaceCanaryError("F_GET_SEALS is unavailable")
    try:
        metadata = os.fstat(descriptor)
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        seals = fcntl.fcntl(descriptor, get_seals)
        offset = os.lseek(descriptor, 0, os.SEEK_CUR)
    except OSError as exc:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "controller runtime descriptor is invalid"
        ) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size != binding.size
        or flags & os.O_ACCMODE != os.O_RDONLY
        or seals != _required_seals()
        or os.get_inheritable(descriptor)
        or offset != 0
        or _hash_descriptor(descriptor, binding.size) != binding.content_sha256
    ):
        raise DevelopmentRuntimeNamespaceCanaryError(
            "controller runtime descriptor differs from its sealed binding"
        )


def _strict_child_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError("probe JSON contains an invalid or duplicate key")
        result[key] = value
    return result


def _reject_json_number(_value: str) -> object:
    raise ValueError("probe JSON contains a non-integer number")


def _load_probe_observation(payload: bytes) -> dict[str, object]:
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "fixed probe output is not exactly one framed line"
        )
    try:
        value = json.loads(
            payload[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_child_object,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "fixed probe emitted malformed JSON"
        ) from exc
    if type(value) is not dict:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "fixed probe output is not an exact object"
        )
    return value


def _validate_probe_observation(
    observation: Mapping[str, object],
    probe: DevelopmentRuntimeNamespaceBinding,
    limits: DevelopmentRuntimeNamespaceCanaryLimits,
) -> tuple[str, int, int, int, int, int]:
    keys = {
        "schema_version",
        "probe_sha256",
        "probe_size",
        "probe_mode",
        "probe_uid",
        "probe_gid",
        "probe_nlink",
        "probe_chmod_blocked",
        "write_blocked",
        "source_fd_leak_count",
        "root_chmod_blocked",
        "root_chmod_then_write_blocked",
        "root_writable",
        "workspace_writable",
        "non_loopback_interfaces",
        "host_home_visible",
        "host_sys_visible",
    }
    if type(observation) is not dict or set(observation) != keys:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "fixed probe output shape is invalid"
        )
    digest = _lower_sha256(observation.get("probe_sha256"), what="observed probe_sha256")
    mode_text = observation.get("probe_mode")
    if type(mode_text) is not str or re.fullmatch(r"[0-7]{1,4}", mode_text) is None:
        raise DevelopmentRuntimeNamespaceCanaryError("observed probe mode is invalid")
    mode = int(mode_text, 8)
    numeric_names = (
        "probe_size",
        "probe_uid",
        "probe_gid",
        "probe_nlink",
        "probe_chmod_blocked",
        "write_blocked",
        "source_fd_leak_count",
        "root_chmod_blocked",
        "root_chmod_then_write_blocked",
        "root_writable",
        "workspace_writable",
        "non_loopback_interfaces",
        "host_home_visible",
        "host_sys_visible",
    )
    numbers: dict[str, int] = {}
    for name in numeric_names:
        value = observation.get(name)
        if type(value) is not int or value < 0 or value > 2**63 - 1:
            raise DevelopmentRuntimeNamespaceCanaryError(
                f"fixed probe number {name!r} is invalid"
            )
        numbers[name] = value
    exact: dict[str, object] = {
        "schema_version": "1.0.0",
        "probe_sha256": probe.content_sha256,
        "probe_size": probe.size,
        "probe_mode": f"{probe.mode:o}",
        "probe_uid": limits.uid,
        "probe_gid": limits.gid,
        "probe_nlink": 0,
        "probe_chmod_blocked": 1,
        "write_blocked": 1,
        "source_fd_leak_count": 0,
        "root_chmod_blocked": 1,
        "root_chmod_then_write_blocked": 1,
        "root_writable": 0,
        "workspace_writable": 1,
        "non_loopback_interfaces": 0,
        "host_home_visible": 0,
        "host_sys_visible": 0,
    }
    for name, expected in exact.items():
        if observation.get(name) != expected:
            raise DevelopmentRuntimeNamespaceCanaryError(
                f"fixed probe observation {name!r} differs from its contract"
            )
    return (
        digest,
        numbers["probe_size"],
        mode,
        numbers["probe_uid"],
        numbers["probe_gid"],
        numbers["probe_nlink"],
    )


def _expected_probe_output_bytes(
    *,
    digest: str,
    size: int,
    mode: int,
    uid: int,
    gid: int,
    nlink: int = 0,
) -> bytes:
    record: dict[str, object] = {
        "schema_version": "1.0.0",
        "probe_sha256": digest,
        "probe_size": size,
        "probe_mode": f"{mode:o}",
        "probe_uid": uid,
        "probe_gid": gid,
        "probe_nlink": nlink,
        "probe_chmod_blocked": 1,
        "write_blocked": 1,
        "source_fd_leak_count": 0,
        "root_chmod_blocked": 1,
        "root_chmod_then_write_blocked": 1,
        "root_writable": 0,
        "workspace_writable": 1,
        "non_loopback_interfaces": 0,
        "host_home_visible": 0,
        "host_sys_visible": 0,
    }
    return json.dumps(record, separators=(",", ":")).encode("utf-8") + b"\n"


def _clean_user_systemd_environment() -> dict[str, str]:
    uid = os.getuid()
    runtime = f"/run/user/{uid}"
    try:
        home = pwd.getpwuid(uid).pw_dir
    except (KeyError, OSError):
        home = "/nonexistent"
    if type(home) is not str or not os.path.isabs(home):
        home = "/nonexistent"
    return {
        "PATH": _SAFE_PATH,
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": home,
        "XDG_RUNTIME_DIR": runtime,
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime}/bus",
    }


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError, PermissionError):
        try:
            process.kill()
        except OSError:
            pass


def _kill_unit(
    systemctl: _PinnedExecutable,
    unit_name: str,
    timeout_seconds: float,
) -> None:
    argv = (
        systemctl.path,
        "--user",
        "kill",
        "--kill-who=all",
        "--signal=SIGKILL",
        unit_name,
    )
    try:
        subprocess.run(
            argv,
            executable=f"/proc/self/fd/{systemctl.descriptor}",
            pass_fds=(systemctl.descriptor,),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            close_fds=True,
            env=_clean_user_systemd_environment(),
            timeout=max(timeout_seconds, 0.1),
            check=False,
        )
    except (OSError, subprocess.SubprocessError, TypeError, ValueError):
        pass


def _terminate_fixed_canary(
    process: subprocess.Popen[bytes],
    systemctl: _PinnedExecutable,
    unit_name: str,
    grace_seconds: float,
) -> None:
    _kill_unit(systemctl, unit_name, grace_seconds)
    _kill_process_group(process)


def _terminate_and_reap_fixed_canary(
    process: subprocess.Popen[bytes],
    systemctl: _PinnedExecutable,
    unit_name: str,
    grace_seconds: float,
) -> int | None:
    _terminate_fixed_canary(process, systemctl, unit_name, grace_seconds)
    try:
        return process.wait(timeout=max(grace_seconds, 0.1))
    except (OSError, subprocess.TimeoutExpired):
        _kill_process_group(process)
        try:
            return process.wait(timeout=max(grace_seconds, 0.1))
        except (OSError, subprocess.TimeoutExpired):
            return None


def _close_stream(stream: object) -> None:
    close = getattr(stream, "close", None)
    if callable(close):
        try:
            close()
        except OSError:
            pass


def _run_fixed_namespace_canary(
    argv: tuple[str, ...],
    *,
    stdin: bytes,
    unit_name: str,
    systemd_run: _PinnedExecutable,
    systemctl: _PinnedExecutable,
    limits: DevelopmentRuntimeNamespaceCanaryLimits,
) -> DevelopmentRuntimeNamespaceCanaryResult:
    """Execute only the fixed canary under cap-plus-one bounded capture."""

    if (
        stdin != _FIXED_PROBE_SOURCE.encode("utf-8")
        or sha256(stdin).hexdigest()
        != DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_PROBE_SHA256
        or not argv
        or argv[0] != systemd_run.path
        or _validate_unit_name(unit_name) != unit_name
    ):
        raise DevelopmentRuntimeNamespaceCanaryError(
            "runner accepts only the hash-bound fixed namespace probe"
        )
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            argv,
            executable=f"/proc/self/fd/{systemd_run.descriptor}",
            pass_fds=(systemd_run.descriptor,),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            start_new_session=True,
            env=_clean_user_systemd_environment(),
        )
    except (OSError, subprocess.SubprocessError, TypeError, ValueError):
        return DevelopmentRuntimeNamespaceCanaryResult(
            returncode=None,
            launch_error=True,
        )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        _terminate_and_reap_fixed_canary(
            process,
            systemctl,
            unit_name,
            float(limits.kill_grace_seconds),
        )
        for stream in (process.stdin, process.stdout, process.stderr):
            _close_stream(stream)
        return DevelopmentRuntimeNamespaceCanaryResult(
            returncode=None,
            launch_error=True,
        )

    selector: selectors.BaseSelector | None = None
    streams: dict[int, tuple[str, object]] = {}
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    timed_out = False
    truncated = False
    killed = False
    returncode: int | None = None
    try:
        try:
            process.stdin.write(stdin)
        except (BrokenPipeError, OSError):
            pass
        finally:
            _close_stream(process.stdin)

        streams = {
            process.stdout.fileno(): ("stdout", process.stdout),
            process.stderr.fileno(): ("stderr", process.stderr),
        }
        selector = selectors.DefaultSelector()
        for descriptor, (_name, stream) in streams.items():
            os.set_blocking(descriptor, False)
            selector.register(stream, selectors.EVENT_READ, descriptor)
        deadline = monotonic() + float(limits.timeout_seconds)
        while selector.get_map():
            remaining = deadline - monotonic()
            if remaining <= 0:
                timed_out = True
                returncode = _terminate_and_reap_fixed_canary(
                    process,
                    systemctl,
                    unit_name,
                    float(limits.kill_grace_seconds),
                )
                killed = True
                break
            for key, _mask in selector.select(min(remaining, 0.05)):
                descriptor = int(key.data)
                name, stream = streams[descriptor]
                available = limits.max_output_bytes - len(buffers[name])
                try:
                    block = os.read(descriptor, min(64 * 1024, available + 1))
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(stream)
                    _close_stream(stream)
                    continue
                if len(block) > available:
                    buffers[name].extend(block[:available])
                    truncated = True
                    returncode = _terminate_and_reap_fixed_canary(
                        process,
                        systemctl,
                        unit_name,
                        float(limits.kill_grace_seconds),
                    )
                    killed = True
                    break
                buffers[name].extend(block)
            if killed:
                break
        if not killed:
            try:
                returncode = process.wait(
                    timeout=float(limits.kill_grace_seconds)
                )
            except subprocess.TimeoutExpired:
                timed_out = True
                returncode = _terminate_and_reap_fixed_canary(
                    process,
                    systemctl,
                    unit_name,
                    float(limits.kill_grace_seconds),
                )
        return DevelopmentRuntimeNamespaceCanaryResult(
            returncode=returncode,
            stdout=bytes(buffers["stdout"]),
            stderr=bytes(buffers["stderr"]),
            timed_out=timed_out,
            output_truncated=truncated,
        )
    except BaseException:
        _terminate_and_reap_fixed_canary(
            process,
            systemctl,
            unit_name,
            float(limits.kill_grace_seconds),
        )
        raise
    finally:
        if selector is not None:
            try:
                selector.close()
            except OSError:
                pass
        for _name, stream in streams.values():
            _close_stream(stream)
        _close_stream(process.stdin)
        _close_stream(process.stdout)
        _close_stream(process.stderr)


def _call_runner(
    runner: NamespaceCanaryRunner,
    argv: tuple[str, ...],
    *,
    unit_name: str,
    systemd_run: _PinnedExecutable,
    systemctl: _PinnedExecutable,
    limits: DevelopmentRuntimeNamespaceCanaryLimits,
) -> DevelopmentRuntimeNamespaceCanaryResult:
    try:
        result = runner(
            argv,
            stdin=_FIXED_PROBE_SOURCE.encode("utf-8"),
            unit_name=unit_name,
            systemd_run=systemd_run,
            systemctl=systemctl,
            limits=limits,
        )
    except DevelopmentRuntimeNamespaceCanaryError:
        raise
    except (
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as exc:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "fixed namespace canary runner failed closed"
        ) from exc
    if type(result) is not DevelopmentRuntimeNamespaceCanaryResult:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "fixed namespace canary runner returned the wrong type"
        )
    result.__post_init__()
    return result


def _result_observation(
    result: DevelopmentRuntimeNamespaceCanaryResult,
    probe: DevelopmentRuntimeNamespaceBinding,
    limits: DevelopmentRuntimeNamespaceCanaryLimits,
) -> tuple[dict[str, object], tuple[str, int, int, int, int, int]]:
    if result.launch_error:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "fixed namespace canary could not be launched"
        )
    if result.timed_out:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "fixed namespace canary timed out"
        )
    if result.output_truncated:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "fixed namespace canary exceeded its output bound"
        )
    if result.returncode != 0:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "fixed namespace canary returned nonzero"
        )
    if result.stderr:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "fixed namespace canary emitted stderr"
        )
    if len(result.stdout) > limits.max_output_bytes:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "fixed namespace canary stdout exceeds its declared bound"
        )
    observation = _load_probe_observation(result.stdout)
    values = _validate_probe_observation(observation, probe, limits)
    expected_output = _expected_probe_output_bytes(
        digest=probe.content_sha256,
        size=probe.size,
        mode=probe.mode,
        uid=limits.uid,
        gid=limits.gid,
    )
    if result.stdout != expected_output:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "fixed probe output bytes differ from the frozen frame"
        )
    return observation, values


def _construct_evidence(
    *,
    snapshot: DevelopmentRuntimeFdSnapshot,
    bindings: tuple[DevelopmentRuntimeNamespaceBinding, ...],
    probe: DevelopmentRuntimeNamespaceBinding,
    unit_name: str,
    argv: tuple[str, ...],
    systemd_run: _PinnedExecutable,
    bwrap: _PinnedExecutable,
    systemctl: _PinnedExecutable,
    result: DevelopmentRuntimeNamespaceCanaryResult,
    observed: tuple[str, int, int, int, int, int],
    limits: DevelopmentRuntimeNamespaceCanaryLimits,
    runner_injected: bool,
) -> DevelopmentRuntimeNamespaceCanaryEvidence:
    digest, size, mode, uid, gid, nlink = observed
    verified = False
    launch_contract = _normalized_launch_contract(argv, bindings)
    fields: dict[str, object] = {
        "source_snapshot_sha256": snapshot.snapshot_sha256,
        "source_projection_sha256": snapshot.source_projection_sha256,
        "bindings": bindings,
        "binding_index_sha256": _binding_index_sha256(bindings),
        "unit_name": unit_name,
        "limits": limits,
        "argv_sha256": sha256(
            canonical_development_runtime_json_bytes(list(argv))
        ).hexdigest(),
        "launch_contract_argv": launch_contract,
        "launch_contract_sha256": sha256(
            canonical_development_runtime_json_bytes(list(launch_contract))
        ).hexdigest(),
        "systemd_run_path": systemd_run.path,
        "systemd_run_sha256": systemd_run.sha256,
        "bwrap_path": bwrap.path,
        "bwrap_sha256": bwrap.sha256,
        "systemctl_path": systemctl.path,
        "systemctl_sha256": systemctl.sha256,
        "probe_source_sha256": DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_PROBE_SHA256,
        "probe_regular_path": probe.destination_path,
        "expected_probe_sha256": probe.content_sha256,
        "expected_probe_size": probe.size,
        "expected_probe_mode": probe.mode,
        "namespace_uid": limits.uid,
        "namespace_gid": limits.gid,
        "reported_probe_sha256": digest,
        "reported_probe_size": size,
        "reported_probe_mode": mode,
        "reported_probe_uid": uid,
        "reported_probe_gid": gid,
        "reported_probe_nlink": nlink,
        "reported_probe_chmod_blocked": 1,
        "reported_payload_write_blocked": 1,
        "reported_persistent_fd_count_at_or_above_three": 0,
        "reported_root_chmod_blocked": 1,
        "reported_root_chmod_then_write_blocked": 1,
        "reported_root_writable": 0,
        "reported_workspace_writable": 1,
        "reported_non_loopback_interfaces": 0,
        "reported_host_home_visible": 0,
        "reported_host_sys_visible": 0,
        "stdout_bytes": len(result.stdout),
        "stdout_sha256": sha256(result.stdout).hexdigest(),
        "stderr_bytes": len(result.stderr),
        "stderr_sha256": sha256(result.stderr).hexdigest(),
        "runner_injected": runner_injected,
        "default_runner_invoked": not runner_injected,
        "payload_write_blocked_verified": verified,
        "probe_chmod_blocked_verified": verified,
        "activation_fds_closed_verified": verified,
        "root_chmod_blocked_verified": verified,
        "root_read_only_verified": verified,
        "workspace_writable_verified": verified,
        "no_non_loopback_interfaces_verified": verified,
        "host_home_absent_verified": verified,
        "host_sys_absent_verified": verified,
        "systemd_openfile_handoff_verified": verified,
        "bubblewrap_ro_bind_data_handoff_verified": verified,
        "projected_probe_payload_verified": verified,
        "projected_probe_mode_verified": verified,
        "fixed_probe_executed": verified,
    }
    # ``limits`` is already bound into argv and its hash; retain the exact
    # argument to make accidental removal from this construction visible.
    limits.__post_init__()
    temporary = object.__new__(DevelopmentRuntimeNamespaceCanaryEvidence)
    for item in dataclass_fields(DevelopmentRuntimeNamespaceCanaryEvidence):
        if item.name == "evidence_sha256":
            value: object = "0" * 64
        elif item.name in fields:
            value = fields[item.name]
        elif item.default is not MISSING:
            value = item.default
        else:  # pragma: no cover - construction table covers required fields
            raise DevelopmentRuntimeNamespaceCanaryError(
                f"evidence construction omitted {item.name!r}"
            )
        object.__setattr__(temporary, item.name, value)
    digest_value = _compute_evidence_sha256(temporary)
    return DevelopmentRuntimeNamespaceCanaryEvidence(
        evidence_sha256=digest_value,
        **fields,  # type: ignore[arg-type]
    )


def run_development_runtime_namespace_canary(
    snapshot: DevelopmentRuntimeFdSnapshot,
    *,
    limits: DevelopmentRuntimeNamespaceCanaryLimits | None = None,
    systemd_run: str = "/usr/bin/systemd-run",
    bwrap: str = "/usr/bin/bwrap",
    systemctl: str = "/usr/bin/systemctl",
    runner: NamespaceCanaryRunner | None = None,
) -> DevelopmentRuntimeNamespaceCanaryEvidence:
    """Run only the fixed BusyBox namespace canary, never a candidate.

    An injected runner remains useful for parser and failure-path tests, but
    evidence produced with one cannot verify that either handoff occurred.
    """

    selected = limits if limits is not None else DevelopmentRuntimeNamespaceCanaryLimits()
    if type(selected) is not DevelopmentRuntimeNamespaceCanaryLimits:
        raise TypeError("limits must be exact DevelopmentRuntimeNamespaceCanaryLimits")
    selected.__post_init__()
    bindings = _validate_snapshot_for_canary(snapshot, selected)
    probe = _resolve_probe_binding(snapshot, bindings)
    if sha256(_FIXED_PROBE_SOURCE.encode("utf-8")).hexdigest() != DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_PROBE_SHA256:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "fixed probe source differs from its import-time digest"
        )
    unit_name = (
        DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_UNIT_PREFIX
        + secrets.token_hex(16)
        + ".service"
    )
    _validate_unit_name(unit_name)
    pinned: list[_PinnedExecutable] = []
    regular_fds: list[int] = []
    try:
        pinned_systemd = _open_pinned_executable(systemd_run, what="systemd-run")
        pinned.append(pinned_systemd)
        pinned_bwrap = _open_pinned_executable(bwrap, what="bwrap")
        pinned.append(pinned_bwrap)
        pinned_systemctl = _open_pinned_executable(systemctl, what="systemctl")
        pinned.append(pinned_systemctl)
        for binding in bindings:
            descriptor = snapshot.duplicate_regular_fd(binding.destination_path)
            regular_fds.append(descriptor)
            _verify_controller_regular_fd(descriptor, binding)
        argv = build_development_runtime_namespace_canary_argv(
            snapshot,
            controller_pid=os.getpid(),
            controller_regular_fds=tuple(regular_fds),
            bwrap_controller_fd=pinned_bwrap.descriptor,
            systemd_run=pinned_systemd.path,
            unit_name=unit_name,
            limits=selected,
        )
        selected_runner = runner if runner is not None else _run_fixed_namespace_canary
        result = _call_runner(
            selected_runner,
            argv,
            unit_name=unit_name,
            systemd_run=pinned_systemd,
            systemctl=pinned_systemctl,
            limits=selected,
        )
        _unused_observation, observed = _result_observation(
            result,
            probe,
            selected,
        )
        for executable, name in (
            (pinned_systemd, "systemd-run"),
            (pinned_bwrap, "bwrap"),
            (pinned_systemctl, "systemctl"),
        ):
            _verify_pinned_executable(executable, what=name)
        for descriptor, binding in zip(regular_fds, bindings, strict=True):
            _verify_controller_regular_fd(descriptor, binding)
        return _construct_evidence(
            snapshot=snapshot,
            bindings=bindings,
            probe=probe,
            unit_name=unit_name,
            argv=argv,
            systemd_run=pinned_systemd,
            bwrap=pinned_bwrap,
            systemctl=pinned_systemctl,
            result=result,
            observed=observed,
            limits=selected,
            runner_injected=runner is not None,
        )
    except DevelopmentRuntimeNamespaceCanaryError:
        raise
    except (DevelopmentRuntimeFdSnapshotError, OSError, TypeError, ValueError) as exc:
        raise DevelopmentRuntimeNamespaceCanaryError(
            "fixed namespace canary failed closed"
        ) from exc
    finally:
        while regular_fds:
            descriptor = regular_fds.pop()
            try:
                os.close(descriptor)
            except OSError:
                pass
        while pinned:
            executable = pinned.pop()
            try:
                os.close(executable.descriptor)
            except OSError:
                pass


__all__ = [
    "DEVELOPMENT_RUNTIME_NAMESPACE_ACTIVATION_FD_START",
    "DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_ALGORITHM",
    "DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_KIND",
    "DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_PROBE_PATH",
    "DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_PROBE_SHA256",
    "DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_SCHEMA_VERSION",
    "DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_UNIT_PREFIX",
    "DEVELOPMENT_RUNTIME_NAMESPACE_CANARY_VERSION",
    "DevelopmentRuntimeNamespaceBinding",
    "DevelopmentRuntimeNamespaceCanaryError",
    "DevelopmentRuntimeNamespaceCanaryEvidence",
    "DevelopmentRuntimeNamespaceCanaryLimits",
    "DevelopmentRuntimeNamespaceCanaryResult",
    "build_development_runtime_namespace_canary_argv",
    "run_development_runtime_namespace_canary",
    "verify_development_runtime_namespace_canary_evidence",
]
