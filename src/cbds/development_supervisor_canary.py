"""Candidate-input-free native supervisor lifecycle canary.

This module projects one caller-pinned, static supervisor binary into an empty
Bubblewrap PID namespace and sends only the nine fixed requests defined by
``development_supervisor_protocol``.  It never accepts a candidate program,
command, argv, environment, fixture, verifier, or score.  The supervisor
binary is copied into a sealed memfd and mounted with ``--ro-bind-data``; no
mutable source path is mounted into the namespace.

The observations are deliberately nonauthorizing.  A locally supplied binary,
Bubblewrap executable, or injected runner has no external trust anchor, and
the fixed child seccomp policy is not the policy required by synthesized Bash.
Successful evidence therefore leaves the general supervisor, candidate
execution, model-selection, scoring, and claim flags false.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import MISSING, dataclass, fields as dataclass_fields
import fcntl
from hashlib import sha256
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
import tempfile
from time import monotonic
from typing import Final

from .development_runtime_bundle import (
    DevelopmentRuntimeBundleError,
    DevelopmentRuntimeExecutable,
    build_development_runtime_bundle_manifest,
    canonical_development_runtime_json_bytes,
)
from .development_supervisor_protocol import (
    DEVELOPMENT_SUPERVISOR_RESULT_BYTES,
    DevelopmentSupervisorFlag,
    DevelopmentSupervisorOutcome,
    DevelopmentSupervisorProtocolError,
    DevelopmentSupervisorRequest,
    DevelopmentSupervisorResult,
    DevelopmentSupervisorScenario,
    canonical_development_supervisor_request_record_bytes,
    canonical_development_supervisor_result_record_bytes,
    encode_development_supervisor_request,
    parse_development_supervisor_result,
    validate_development_supervisor_result_binding,
)


DEVELOPMENT_SUPERVISOR_CANARY_SCHEMA_VERSION: Final[str] = "1.0.0"
DEVELOPMENT_SUPERVISOR_CANARY_VERSION: Final[str] = "1.0.0"
DEVELOPMENT_SUPERVISOR_CANARY_KIND: Final[str] = (
    "cbds-development-supervisor-lifecycle-canary"
)
DEVELOPMENT_SUPERVISOR_CANARY_ALGORITHM: Final[str] = (
    "sealed-static-supervisor-bwrap-pid1-fixed-scenarios-v1"
)
DEVELOPMENT_SUPERVISOR_CANARY_PATH: Final[str] = "/cbds-supervisor"
DEVELOPMENT_SUPERVISOR_CANARY_SCENARIOS: Final[
    tuple[DevelopmentSupervisorScenario, ...]
] = tuple(DevelopmentSupervisorScenario)

_SHA256_HEX_LENGTH: Final[int] = 64
_HASH_CHUNK_BYTES: Final[int] = 1024 * 1024
_MAXIMUM_EXECUTABLE_BYTES: Final[int] = 32 * 1024 * 1024
_STDERR_CAPTURE_BYTES: Final[int] = 4096
_OUTER_GRACE_SECONDS: Final[float] = 2.0
_WORKSPACE_BYTES: Final[int] = 1024 * 1024
_SAFE_PATH: Final[str] = (
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)
_SOURCE_PATH: Final[Path] = (
    Path(__file__).resolve().parents[2]
    / "native"
    / "cbds-development-supervisor.c"
)
_COMPILER_PATH: Final[str] = "/usr/bin/gcc"
_SYSTEM_BWRAP_PATH: Final[str] = "/usr/bin/bwrap"
_SYSTEMD_RUN_PATH: Final[str] = "/usr/bin/systemd-run"
_SYSTEMCTL_PATH: Final[str] = "/usr/bin/systemctl"
_BUILD_ARGUMENTS: Final[tuple[str, ...]] = (
    "-std=gnu17",
    "-O2",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-static-pie",
)
_UNIT_RE: Final[re.Pattern[str]] = re.compile(
    r"cbds-supervisor-canary-v1-[0-9a-f]{32}-[1-9]\.service"
)
_OPENFILE_NAME: Final[str] = "cbds-supervisor-v1"

_MANDATORY_REPORTED_FLAGS: Final[DevelopmentSupervisorFlag] = (
    DevelopmentSupervisorFlag.REQUEST_VALIDATED
    | DevelopmentSupervisorFlag.PID1_VERIFIED
    | DevelopmentSupervisorFlag.NO_NEW_PRIVS
    | DevelopmentSupervisorFlag.DUMPABLE_DISABLED
    | DevelopmentSupervisorFlag.SECCOMP_INSTALLED
    | DevelopmentSupervisorFlag.PRIMARY_REAPED
    | DevelopmentSupervisorFlag.ALL_DESCENDANTS_REAPED
    | DevelopmentSupervisorFlag.SOLE_PID1
)

_NORMAL_STDOUT: Final[bytes] = b"child-normal-stdout\n"
_NORMAL_STDERR: Final[bytes] = b"child-normal-stderr\n"
_ESCAPE_STDOUT: Final[bytes] = b"escape-ready\n"
_ZOMBIE_STDOUT: Final[bytes] = b"zombie-ready\n"
_SPOOF_STDOUT: Final[bytes] = b"CBDSSRS1-child-spoof\n"


class DevelopmentSupervisorCanaryError(ValueError):
    """Raised when the fixed lifecycle canary fails closed."""


@dataclass(frozen=True, slots=True)
class DevelopmentSupervisorCanaryProcessResult:
    """Bounded outer observation of one fixed Bubblewrap invocation."""

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


SupervisorCanaryRunner = Callable[..., DevelopmentSupervisorCanaryProcessResult]


@dataclass(frozen=True, slots=True)
class _PinnedFile:
    path: str
    size: int
    sha256: str
    identity: tuple[int, ...]
    descriptor: int


@dataclass(frozen=True, slots=True)
class DevelopmentSupervisorScenarioEvidence:
    """One parsed fixed-scenario request/result pair."""

    request: DevelopmentSupervisorRequest
    result: DevelopmentSupervisorResult
    request_record_sha256: str
    result_record_sha256: str
    scenario_evidence_sha256: str

    def __post_init__(self) -> None:
        _validate_scenario_evidence(self)

    def to_record(self) -> dict[str, object]:
        _validate_scenario_evidence(self)
        return _scenario_record(self, include_self_digest=True)


@dataclass(frozen=True, slots=True)
class DevelopmentSupervisorCanaryEvidence:
    """Descriptor-free, nonauthorizing result of the complete fixed suite."""

    native_source_path: str
    native_source_sha256: str
    compiler_path: str
    compiler_sha256: str
    compiler_size: int
    build_contract_argv: tuple[str, ...]
    build_contract_sha256: str
    supervisor_path: str
    supervisor_sha256: str
    supervisor_size: int
    bwrap_path: str
    bwrap_sha256: str
    bwrap_size: int
    systemd_run_path: str
    systemd_run_sha256: str
    systemd_run_size: int
    systemctl_path: str
    systemctl_sha256: str
    systemctl_size: int
    suite_nonce_hex: str
    suite_nonce_sha256: str
    launch_contract_argv: tuple[str, ...]
    launch_contract_sha256: str
    scenarios: tuple[DevelopmentSupervisorScenarioEvidence, ...]
    scenario_index_sha256: str
    runner_injected: bool
    default_runner_invoked: bool
    evidence_sha256: str
    schema_version: str = DEVELOPMENT_SUPERVISOR_CANARY_SCHEMA_VERSION
    canary_version: str = DEVELOPMENT_SUPERVISOR_CANARY_VERSION
    kind: str = DEVELOPMENT_SUPERVISOR_CANARY_KIND
    algorithm: str = DEVELOPMENT_SUPERVISOR_CANARY_ALGORITHM
    candidate_input_api_absent: bool = True
    complete_fixed_scenario_vocabulary_used: bool = True
    native_source_identity_recorded: bool = True
    local_fixed_source_build_reproduced: bool = True
    static_supervisor_elf_validated: bool = True
    sealed_supervisor_payload_prepared: bool = True
    direct_bwrap_pid_namespace_requested: bool = True
    systemd_cgroup_envelope_requested: bool = True
    exact_result_frames_validated: bool = True
    reported_pid1_for_all_scenarios: bool = True
    reported_child_security_setup_for_all_scenarios: bool = True
    reported_all_descendants_reaped_for_all_scenarios: bool = True
    reported_sole_pid1_after_all_scenarios: bool = True
    externally_trusted_native_source: bool = False
    externally_trusted_supervisor_binary: bool = False
    externally_trusted_bwrap: bool = False
    externally_trusted_systemd: bool = False
    fixed_supervisor_executed_verified: bool = False
    trusted_pid1_supervisor_implemented: bool = False
    child_seccomp_filter_implemented: bool = False
    cumulative_cpu_time_enforced: bool = False
    exact_tool_policy_enforced: bool = False
    runtime_data_and_dlopen_closure_verified: bool = False
    candidate_execution_authorized: bool = False
    candidate_executed: bool = False
    scored_evaluation_eligible: bool = False
    model_selection_eligible: bool = False
    claim_pipeline_eligible: bool = False

    def __post_init__(self) -> None:
        _validate_evidence(self)

    def to_record(self) -> dict[str, object]:
        _validate_evidence(self)
        return _evidence_record(self, include_self_digest=True)


def _lower_sha256(value: object, *, what: str) -> str:
    if (
        type(value) is not str
        or len(value) != _SHA256_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DevelopmentSupervisorCanaryError(f"{what} must be lowercase SHA-256")
    return value


def _validate_absolute_path(value: object, *, what: str) -> str:
    if type(value) is not str:
        raise DevelopmentSupervisorCanaryError(f"{what} must be exact text")
    path = PurePosixPath(value)
    if (
        not value.startswith("/")
        or value.startswith("//")
        or str(path) != value
        or value == "/"
        or "." in path.parts
        or ".." in path.parts
        or any(character in value for character in ("\x00", "\r", "\n"))
    ):
        raise DevelopmentSupervisorCanaryError(
            f"{what} must be normalized and absolute"
        )
    return value


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
            raise DevelopmentSupervisorCanaryError(
                "descriptor ended before its authenticated size"
            )
        digest.update(block)
        offset += len(block)
    if os.pread(descriptor, 1, size):
        raise DevelopmentSupervisorCanaryError(
            "descriptor grew beyond its authenticated size"
        )
    return digest.hexdigest()


def _open_pinned_file(
    path_text: str,
    *,
    what: str,
    executable: bool,
    maximum_bytes: int,
) -> _PinnedFile:
    _validate_absolute_path(path_text, what=what)
    try:
        resolved = os.path.realpath(path_text, strict=True)
    except OSError as exc:
        raise DevelopmentSupervisorCanaryError(f"{what} cannot be resolved") from exc
    _validate_absolute_path(resolved, what=what)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if type(nofollow) is not int or nofollow <= 0:
        raise DevelopmentSupervisorCanaryError("O_NOFOLLOW is unavailable")
    descriptor: int | None = None
    try:
        descriptor = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC | nofollow)
        opened = os.fstat(descriptor)
        named = os.stat(resolved, follow_symlinks=False)
        identity = _metadata_identity(opened)
        if (
            identity != _metadata_identity(named)
            or not stat.S_ISREG(opened.st_mode)
            or (executable and not opened.st_mode & 0o111)
            or opened.st_size <= 0
            or opened.st_size > maximum_bytes
            or os.get_inheritable(descriptor)
        ):
            raise DevelopmentSupervisorCanaryError(
                f"{what} is not a pinned bounded regular file"
            )
        result = _PinnedFile(
            path=resolved,
            size=opened.st_size,
            sha256=_hash_descriptor(descriptor, opened.st_size),
            identity=identity,
            descriptor=descriptor,
        )
        descriptor = None
        return result
    except DevelopmentSupervisorCanaryError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise DevelopmentSupervisorCanaryError(f"{what} pinning failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _verify_pinned_file(value: _PinnedFile, *, what: str) -> None:
    try:
        opened = os.fstat(value.descriptor)
        named = os.stat(value.path, follow_symlinks=False)
    except OSError as exc:
        raise DevelopmentSupervisorCanaryError(
            f"{what} disappeared during the canary"
        ) from exc
    if (
        _metadata_identity(opened) != value.identity
        or _metadata_identity(named) != value.identity
        or os.get_inheritable(value.descriptor)
        or _hash_descriptor(value.descriptor, value.size) != value.sha256
    ):
        raise DevelopmentSupervisorCanaryError(f"{what} changed during the canary")


def _validate_static_supervisor_elf(value: _PinnedFile) -> None:
    try:
        manifest = build_development_runtime_bundle_manifest(
            (
                DevelopmentRuntimeExecutable(
                    name="cbds-development-supervisor",
                    source_path=value.path,
                    expected_sha256=value.sha256,
                ),
            ),
            allowed_source_roots=(str(Path(value.path).parent),),
            library_search_directories=(),
            maximum_file_bytes=_MAXIMUM_EXECUTABLE_BYTES,
            maximum_total_regular_payload_bytes=_MAXIMUM_EXECUTABLE_BYTES,
            maximum_manifest_entries=16,
        )
    except (DevelopmentRuntimeBundleError, OSError, TypeError, ValueError) as exc:
        raise DevelopmentSupervisorCanaryError(
            "supervisor is not a closed static ELF executable"
        ) from exc
    entries = manifest.get("entries")
    closure = manifest.get("closure")
    if (
        type(entries) is not list
        or len(entries) != 1
        or type(entries[0]) is not dict
        or entries[0].get("destination_path") != value.path
        or entries[0].get("kind") != "regular"
        or entries[0].get("sha256") != value.sha256
        or type(entries[0].get("elf")) is not dict
        or entries[0]["elf"].get("pt_interp") is not None
        or entries[0]["elf"].get("dt_needed") != []
        or type(closure) is not dict
        or closure.get("regular_file_count") != 1
        or closure.get("symlink_count") != 0
    ):
        raise DevelopmentSupervisorCanaryError(
            "supervisor static ELF closure inventory is not exact"
        )


def _rebuild_fixed_supervisor(
    source: _PinnedFile,
    compiler: _PinnedFile,
) -> tuple[tempfile.TemporaryDirectory[str], _PinnedFile, tuple[str, ...]]:
    """Compile only the pinned repository source with one frozen command."""

    temporary = tempfile.TemporaryDirectory(
        prefix="cbds-development-supervisor-build-"
    )
    output = Path(temporary.name) / "cbds-development-supervisor"
    source_descriptor_path = f"/proc/self/fd/{source.descriptor}"
    source_mapping = (
        f"-ffile-prefix-map={source_descriptor_path}={str(_SOURCE_PATH)}"
    )
    argv = (
        compiler.path,
        *_BUILD_ARGUMENTS,
        source_mapping,
        "-x",
        "c",
        source_descriptor_path,
        "-o",
        str(output),
    )
    process: subprocess.Popen[bytes] | None = None
    built: _PinnedFile | None = None
    try:
        process = subprocess.Popen(
            argv,
            executable=f"/proc/self/fd/{compiler.descriptor}",
            pass_fds=(compiler.descriptor, source.descriptor),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            close_fds=True,
            start_new_session=True,
            env=_clean_environment(),
        )
        try:
            returncode = process.wait(timeout=30.0)
        except subprocess.TimeoutExpired as exc:
            _terminate_and_reap(process)
            raise DevelopmentSupervisorCanaryError(
                "fixed supervisor build timed out"
            ) from exc
        if returncode != 0:
            raise DevelopmentSupervisorCanaryError(
                "fixed supervisor build returned nonzero"
            )
        output.chmod(0o555)
        built = _open_pinned_file(
            str(output),
            what="rebuilt supervisor executable",
            executable=True,
            maximum_bytes=_MAXIMUM_EXECUTABLE_BYTES,
        )
        _verify_pinned_file(source, what="native supervisor source")
        _verify_pinned_file(compiler, what="fixed supervisor compiler")
        return temporary, built, argv
    except BaseException:
        try:
            if process is not None and process.poll() is None:
                _terminate_and_reap(process)
        finally:
            if built is not None:
                try:
                    os.close(built.descriptor)
                except OSError:
                    pass
            temporary.cleanup()
        raise


def _required_seal_mask() -> int:
    mask = 0
    for name in ("F_SEAL_SEAL", "F_SEAL_SHRINK", "F_SEAL_GROW", "F_SEAL_WRITE"):
        value = getattr(fcntl, name, None)
        if type(value) is not int or value < 0:
            raise DevelopmentSupervisorCanaryError(
                f"required seal primitive {name} is unavailable"
            )
        mask |= value
    return mask


def _sealed_read_descriptor(source: _PinnedFile) -> int:
    creator = getattr(os, "memfd_create", None)
    cloexec = getattr(os, "MFD_CLOEXEC", None)
    allow_sealing = getattr(os, "MFD_ALLOW_SEALING", None)
    add_seals = getattr(fcntl, "F_ADD_SEALS", None)
    get_seals = getattr(fcntl, "F_GET_SEALS", None)
    if (
        not callable(creator)
        or type(cloexec) is not int
        or type(allow_sealing) is not int
        or type(add_seals) is not int
        or type(get_seals) is not int
    ):
        raise DevelopmentSupervisorCanaryError("sealed memfd primitives are unavailable")
    writable: int | None = None
    readable: int | None = None
    try:
        writable = creator(
            "cbds-development-supervisor",
            flags=cloexec | allow_sealing,
        )
        offset = 0
        while offset < source.size:
            block = os.pread(
                source.descriptor,
                min(_HASH_CHUNK_BYTES, source.size - offset),
                offset,
            )
            if not block:
                raise DevelopmentSupervisorCanaryError(
                    "supervisor source ended during sealed copy"
                )
            view = memoryview(block)
            while view:
                amount = os.write(writable, view)
                if amount <= 0:
                    raise DevelopmentSupervisorCanaryError(
                        "supervisor sealed copy made no progress"
                    )
                view = view[amount:]
            offset += len(block)
        os.fchmod(writable, 0o555)
        fcntl.fcntl(writable, add_seals, _required_seal_mask())
        readable = os.open(
            f"/proc/self/fd/{writable}",
            os.O_RDONLY | os.O_CLOEXEC,
        )
        metadata = os.fstat(readable)
        access = fcntl.fcntl(readable, fcntl.F_GETFL) & os.O_ACCMODE
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o555
            or metadata.st_size != source.size
            or access != os.O_RDONLY
            or fcntl.fcntl(readable, get_seals) != _required_seal_mask()
            or os.get_inheritable(readable)
            or _hash_descriptor(readable, source.size) != source.sha256
        ):
            raise DevelopmentSupervisorCanaryError(
                "sealed supervisor descriptor differs from its pin"
            )
        result = readable
        readable = None
        return result
    except DevelopmentSupervisorCanaryError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise DevelopmentSupervisorCanaryError(
            "cannot prepare sealed supervisor payload"
        ) from exc
    finally:
        if readable is not None:
            os.close(readable)
        if writable is not None:
            os.close(writable)


def build_development_supervisor_canary_argv(
    *,
    supervisor_fd: int,
    bwrap_path: str = "/usr/bin/bwrap",
    uid: int = 65534,
    gid: int = 65534,
) -> tuple[str, ...]:
    """Build the exact fixed PID-namespace argv; no command argument exists."""

    if type(supervisor_fd) is not int or supervisor_fd < 3:
        raise DevelopmentSupervisorCanaryError("supervisor_fd is invalid")
    _validate_absolute_path(bwrap_path, what="bwrap_path")
    for name, value in (("uid", uid), ("gid", gid)):
        if type(value) is not int or value < 1 or value > 2**31 - 1:
            raise DevelopmentSupervisorCanaryError(f"{name} is invalid")
    return (
        bwrap_path,
        "--unshare-all",
        "--unshare-user",
        "--uid",
        str(uid),
        "--gid",
        str(gid),
        "--disable-userns",
        "--assert-userns-disabled",
        "--die-with-parent",
        "--new-session",
        "--as-pid-1",
        "--clearenv",
        "--perms",
        "0555",
        "--ro-bind-data",
        str(supervisor_fd),
        DEVELOPMENT_SUPERVISOR_CANARY_PATH,
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--size",
        str(_WORKSPACE_BYTES),
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
        "/workspace",
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
        DEVELOPMENT_SUPERVISOR_CANARY_PATH,
    )


def _validate_unit_name(value: object) -> str:
    if type(value) is not str or _UNIT_RE.fullmatch(value) is None:
        raise DevelopmentSupervisorCanaryError("supervisor canary unit is invalid")
    return value


def build_development_supervisor_systemd_canary_argv(
    *,
    controller_pid: int,
    supervisor_controller_fd: int,
    bwrap_controller_fd: int,
    unit_name: str,
    systemd_run_path: str = _SYSTEMD_RUN_PATH,
    uid: int = 65534,
    gid: int = 65534,
) -> tuple[str, ...]:
    """Wrap the fixed namespace in a bounded user-systemd service."""

    if type(controller_pid) is not int or controller_pid <= 1:
        raise DevelopmentSupervisorCanaryError("controller_pid is invalid")
    descriptors = (supervisor_controller_fd, bwrap_controller_fd)
    if (
        any(type(value) is not int or value < 3 for value in descriptors)
        or len(set(descriptors)) != len(descriptors)
    ):
        raise DevelopmentSupervisorCanaryError(
            "controller descriptor table is invalid"
        )
    _validate_unit_name(unit_name)
    _validate_absolute_path(systemd_run_path, what="systemd_run_path")
    inner = build_development_supervisor_canary_argv(
        supervisor_fd=3,
        bwrap_path=f"/proc/{controller_pid}/fd/{bwrap_controller_fd}",
        uid=uid,
        gid=gid,
    )
    properties = (
        "MemoryMax=67108864",
        "MemorySwapMax=0",
        "TasksMax=32",
        "CPUQuota=100%",
        "LimitNOFILE=1024",
        "LimitCORE=0",
        "RuntimeMaxSec=5s",
        "TimeoutStopSec=1s",
        "KillMode=control-group",
        "SendSIGKILL=yes",
        "OOMPolicy=kill",
        "NoNewPrivileges=yes",
        "RestrictAddressFamilies=AF_UNIX AF_NETLINK",
        "UMask=0077",
        (
            f"OpenFile=/proc/{controller_pid}/fd/{supervisor_controller_fd}:"
            f"{_OPENFILE_NAME}:read-only"
        ),
    )
    argv: list[str] = [
        systemd_run_path,
        "--user",
        "--wait",
        "--pipe",
        "--collect",
        "--quiet",
        "--service-type=exec",
        "--expand-environment=no",
        f"--unit={unit_name}",
    ]
    for value in properties:
        argv.extend(("--property", value))
    argv.extend(inner)
    return tuple(argv)


def _normalized_launch_contract(argv: tuple[str, ...]) -> tuple[str, ...]:
    if type(argv) is not tuple or any(type(item) is not str for item in argv):
        raise DevelopmentSupervisorCanaryError("launch argv is invalid")
    result = list(argv)
    unit_indexes = [
        index for index, value in enumerate(result) if value.startswith("--unit=")
    ]
    if len(unit_indexes) != 1:
        raise DevelopmentSupervisorCanaryError("launch unit inventory is invalid")
    _validate_unit_name(result[unit_indexes[0]][len("--unit="):])
    result[unit_indexes[0]] = "--unit=@unit"
    openfile_pattern = re.compile(
        r"OpenFile=/proc/([1-9][0-9]*)/fd/([0-9]+):"
        + re.escape(_OPENFILE_NAME)
        + r":read-only"
    )
    openfile_indexes: list[int] = []
    controller_pid: str | None = None
    for index, value in enumerate(result):
        match = openfile_pattern.fullmatch(value)
        if match is None:
            continue
        if int(match.group(2)) < 3:
            raise DevelopmentSupervisorCanaryError("OpenFile descriptor is invalid")
        controller_pid = match.group(1)
        openfile_indexes.append(index)
        result[index] = (
            "OpenFile=@controller-supervisor-fd:"
            + _OPENFILE_NAME
            + ":read-only"
        )
    if len(openfile_indexes) != 1 or controller_pid is None:
        raise DevelopmentSupervisorCanaryError("OpenFile inventory is invalid")
    bwrap_pattern = re.compile(
        r"/proc/" + re.escape(controller_pid) + r"/fd/([0-9]+)"
    )
    bwrap_indexes = [
        index for index, value in enumerate(result)
        if bwrap_pattern.fullmatch(value) is not None
    ]
    if len(bwrap_indexes) != 1:
        raise DevelopmentSupervisorCanaryError(
            "controller bwrap descriptor inventory is invalid"
        )
    match = bwrap_pattern.fullmatch(result[bwrap_indexes[0]])
    if match is None or int(match.group(1)) < 3:
        raise DevelopmentSupervisorCanaryError("controller bwrap fd is invalid")
    result[bwrap_indexes[0]] = "@controller-bwrap-fd"
    try:
        bind = result.index("--ro-bind-data")
    except ValueError as exc:
        raise DevelopmentSupervisorCanaryError(
            "launch argv omits supervisor projection"
        ) from exc
    if bind + 2 >= len(result) or result[bind + 1] != "3":
        raise DevelopmentSupervisorCanaryError("launch supervisor fd is invalid")
    result[bind + 1] = "@service-supervisor-fd"
    return tuple(result)


def _normalized_build_contract(argv: tuple[str, ...]) -> tuple[str, ...]:
    if type(argv) is not tuple or not argv:
        raise DevelopmentSupervisorCanaryError(
            "fixed supervisor build argv is invalid"
        )
    _validate_absolute_path(argv[0], what="fixed compiler path")
    expected_prefix = (argv[0], *_BUILD_ARGUMENTS)
    if (
        type(argv) is not tuple
        or len(argv) != len(expected_prefix) + 6
        or argv[: len(expected_prefix)] != expected_prefix
        or type(argv[-3]) is not str
        or re.fullmatch(r"/proc/self/fd/([0-9]+)", argv[-3]) is None
        or int(argv[-3].rsplit("/", 1)[1]) < 3
        or argv[-6]
        != f"-ffile-prefix-map={argv[-3]}={str(_SOURCE_PATH)}"
        or argv[-5:-3] != ("-x", "c")
        or argv[-2] != "-o"
        or type(argv[-1]) is not str
        or not os.path.isabs(argv[-1])
    ):
        raise DevelopmentSupervisorCanaryError(
            "fixed supervisor build argv is invalid"
        )
    return (
        *expected_prefix,
        f"-ffile-prefix-map=@source-fd={str(_SOURCE_PATH)}",
        "-x",
        "c",
        str(_SOURCE_PATH),
        "-o",
        "@build-output",
    )


def _clean_environment() -> dict[str, str]:
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


def _run_unit_systemctl(
    systemctl: _PinnedFile,
    arguments: tuple[str, ...],
    *,
    capture: bool,
) -> subprocess.CompletedProcess[bytes]:
    stdout: int = subprocess.PIPE if capture else subprocess.DEVNULL
    stderr: int = subprocess.PIPE if capture else subprocess.DEVNULL
    try:
        completed = subprocess.run(
            (
                systemctl.path,
                "--user",
                *arguments,
            ),
            executable=f"/proc/self/fd/{systemctl.descriptor}",
            pass_fds=(systemctl.descriptor,),
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            shell=False,
            close_fds=True,
            env=_clean_environment(),
            timeout=1.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, TypeError, ValueError) as exc:
        raise DevelopmentSupervisorCanaryError(
            "transient supervisor unit control failed"
        ) from exc
    if type(completed.returncode) is not int:
        raise DevelopmentSupervisorCanaryError(
            "transient supervisor unit control returned an invalid status"
        )
    return completed


def _stop_and_verify_unit(systemctl: _PinnedFile, unit_name: str) -> None:
    """Stop one exact transient unit and prove that its cgroup is gone."""

    _validate_unit_name(unit_name)
    # Either action may race a unit which has already become inactive.  The
    # authoritative condition is the exact state query below, not either
    # action's return code.
    for arguments in (
        (
            "kill",
            "--kill-who=all",
            "--signal=SIGKILL",
            unit_name,
        ),
        ("stop", unit_name),
    ):
        try:
            _run_unit_systemctl(systemctl, arguments, capture=False)
        except DevelopmentSupervisorCanaryError:
            pass
    completed = _run_unit_systemctl(
        systemctl,
        (
            "show",
            "--no-pager",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=ControlGroup",
            unit_name,
        ),
        capture=True,
    )
    if (
        completed.returncode != 0
        or type(completed.stdout) is not bytes
        or type(completed.stderr) is not bytes
        or completed.stderr
        or len(completed.stdout) > 1024
    ):
        raise DevelopmentSupervisorCanaryError(
            "transient supervisor unit quiescence could not be verified"
        )
    try:
        lines = completed.stdout.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise DevelopmentSupervisorCanaryError(
            "transient supervisor unit state is invalid"
        ) from exc
    properties: dict[str, str] = {}
    allowed = {"LoadState", "ActiveState", "SubState", "ControlGroup"}
    for line in lines:
        name, separator, value = line.partition("=")
        if not separator or name not in allowed or name in properties:
            raise DevelopmentSupervisorCanaryError(
                "transient supervisor unit state is invalid"
            )
        properties[name] = value
    if (
        properties.get("LoadState") not in {"loaded", "not-found"}
        or properties.get("ActiveState") != "inactive"
        or properties.get("SubState") != "dead"
        or properties.get("ControlGroup") != ""
        or set(properties) != allowed
    ):
        raise DevelopmentSupervisorCanaryError(
            "transient supervisor unit is not inactive and quiescent"
        )


def _terminate_and_reap(
    process: subprocess.Popen[bytes],
    grace: float = 1.0,
    *,
    systemctl: _PinnedFile | None = None,
    unit_name: str | None = None,
) -> None:
    """Kill and synchronously reap, or fail rather than losing ownership."""

    unit_error: DevelopmentSupervisorCanaryError | None = None
    if (systemctl is None) != (unit_name is None):
        unit_error = DevelopmentSupervisorCanaryError(
            "transient supervisor unit cleanup identity is incomplete"
        )
    elif systemctl is not None and unit_name is not None:
        try:
            _stop_and_verify_unit(systemctl, unit_name)
        except DevelopmentSupervisorCanaryError as exc:
            unit_error = exc
    _kill_process_group(process)
    try:
        process.wait(timeout=max(grace, 0.1))
    except (OSError, subprocess.TimeoutExpired):
        _kill_process_group(process)
        try:
            process.wait(timeout=max(grace, 0.1))
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DevelopmentSupervisorCanaryError(
                "outer supervisor process could not be reaped"
            ) from exc
    if unit_error is not None:
        raise unit_error


def _close_stream(stream: object) -> None:
    close = getattr(stream, "close", None)
    if callable(close):
        try:
            close()
        except OSError:
            pass


def _run_fixed_process(
    argv: tuple[str, ...],
    *,
    request_frame: bytes,
    request: DevelopmentSupervisorRequest,
    bwrap: _PinnedFile,
    supervisor_fd: int,
    systemd_run: _PinnedFile,
    systemctl: _PinnedFile,
    unit_name: str,
) -> DevelopmentSupervisorCanaryProcessResult:
    """Run one fixed frame with cap-plus-one outer capture."""

    if (
        request_frame != encode_development_supervisor_request(request)
        or argv != build_development_supervisor_systemd_canary_argv(
            controller_pid=os.getpid(),
            supervisor_controller_fd=supervisor_fd,
            bwrap_controller_fd=bwrap.descriptor,
            unit_name=unit_name,
            systemd_run_path=systemd_run.path,
        )
    ):
        raise DevelopmentSupervisorCanaryError(
            "runner accepts only an exact fixed supervisor request"
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
            env=_clean_environment(),
        )
    except (OSError, subprocess.SubprocessError, TypeError, ValueError):
        return DevelopmentSupervisorCanaryProcessResult(
            returncode=None,
            launch_error=True,
        )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        _terminate_and_reap(
            process,
            systemctl=systemctl,
            unit_name=unit_name,
        )
        return DevelopmentSupervisorCanaryProcessResult(
            returncode=None,
            launch_error=True,
        )

    selector: selectors.BaseSelector | None = None
    streams: dict[int, tuple[str, object]] = {}
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    caps = {
        "stdout": DEVELOPMENT_SUPERVISOR_RESULT_BYTES,
        "stderr": _STDERR_CAPTURE_BYTES,
    }
    timed_out = False
    truncated = False
    returncode: int | None = None
    killed = False
    try:
        try:
            process.stdin.write(request_frame)
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
        deadline = monotonic() + request.timeout_ms / 1000.0 + _OUTER_GRACE_SECONDS
        while selector.get_map():
            remaining = deadline - monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate_and_reap(
                    process,
                    systemctl=systemctl,
                    unit_name=unit_name,
                )
                returncode = process.returncode
                killed = True
                break
            for key, _mask in selector.select(min(remaining, 0.05)):
                descriptor = int(key.data)
                name, stream = streams[descriptor]
                available = caps[name] - len(buffers[name])
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
                    _terminate_and_reap(
                        process,
                        systemctl=systemctl,
                        unit_name=unit_name,
                    )
                    returncode = process.returncode
                    killed = True
                    break
                buffers[name].extend(block)
            if killed:
                break
        if not killed:
            try:
                returncode = process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_and_reap(
                    process,
                    systemctl=systemctl,
                    unit_name=unit_name,
                )
                returncode = process.returncode
            else:
                _stop_and_verify_unit(systemctl, unit_name)
        return DevelopmentSupervisorCanaryProcessResult(
            returncode=returncode,
            stdout=bytes(buffers["stdout"]),
            stderr=bytes(buffers["stderr"]),
            timed_out=timed_out,
            output_truncated=truncated,
        )
    except BaseException:
        if process.poll() is None:
            _terminate_and_reap(
                process,
                systemctl=systemctl,
                unit_name=unit_name,
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


def _fixed_request(
    scenario: DevelopmentSupervisorScenario,
    suite_nonce: bytes,
) -> DevelopmentSupervisorRequest:
    if type(suite_nonce) is not bytes or len(suite_nonce) != 32:
        raise DevelopmentSupervisorCanaryError("suite_nonce must be exactly 32 bytes")
    timeout = 120 if scenario in {
        DevelopmentSupervisorScenario.WALL_TIMEOUT,
        DevelopmentSupervisorScenario.CPU_FANOUT,
    } else 1000
    nonce = sha256(
        b"cbds.development-supervisor-canary.scenario-nonce.v1\0"
        + suite_nonce
        + int(scenario).to_bytes(4, "little")
    ).digest()
    return DevelopmentSupervisorRequest(
        scenario=scenario,
        timeout_ms=timeout,
        stdout_cap=1024,
        stderr_cap=1024,
        nonce=nonce,
    )


def _expected_streams(
    request: DevelopmentSupervisorRequest,
) -> tuple[bytes, bytes]:
    scenario = request.scenario
    if scenario is DevelopmentSupervisorScenario.NORMAL:
        return _NORMAL_STDOUT, _NORMAL_STDERR
    if scenario is DevelopmentSupervisorScenario.DOUBLE_FORK_SETSID:
        return _ESCAPE_STDOUT, b""
    if scenario is DevelopmentSupervisorScenario.ZOMBIE:
        return _ZOMBIE_STDOUT, b""
    if scenario is DevelopmentSupervisorScenario.STDOUT_FLOOD:
        return b"O" * (request.stdout_cap + 1), b""
    if scenario is DevelopmentSupervisorScenario.STDERR_FLOOD:
        return b"", b"E" * (request.stderr_cap + 1)
    if scenario is DevelopmentSupervisorScenario.RESULT_FRAME_SPOOF:
        return _SPOOF_STDOUT, b""
    return b"", b""


def _expected_outcome(
    scenario: DevelopmentSupervisorScenario,
) -> DevelopmentSupervisorOutcome:
    return {
        DevelopmentSupervisorScenario.NORMAL: DevelopmentSupervisorOutcome.NORMAL,
        DevelopmentSupervisorScenario.DOUBLE_FORK_SETSID: DevelopmentSupervisorOutcome.NORMAL,
        DevelopmentSupervisorScenario.ZOMBIE: DevelopmentSupervisorOutcome.NORMAL,
        DevelopmentSupervisorScenario.WALL_TIMEOUT: DevelopmentSupervisorOutcome.WALL_TIMEOUT,
        DevelopmentSupervisorScenario.STDOUT_FLOOD: DevelopmentSupervisorOutcome.STDOUT_OVERFLOW,
        DevelopmentSupervisorScenario.STDERR_FLOOD: DevelopmentSupervisorOutcome.STDERR_OVERFLOW,
        DevelopmentSupervisorScenario.CPU_FANOUT: DevelopmentSupervisorOutcome.WALL_TIMEOUT,
        DevelopmentSupervisorScenario.FORBIDDEN_SYSCALL: DevelopmentSupervisorOutcome.SIGNAL,
        DevelopmentSupervisorScenario.RESULT_FRAME_SPOOF: DevelopmentSupervisorOutcome.NORMAL,
    }[scenario]


def _validate_fixed_result(
    request: DevelopmentSupervisorRequest,
    result: DevelopmentSupervisorResult,
) -> None:
    if result.outcome is not _expected_outcome(request.scenario):
        raise DevelopmentSupervisorCanaryError("fixed scenario outcome is invalid")
    if result.flags & _MANDATORY_REPORTED_FLAGS != _MANDATORY_REPORTED_FLAGS:
        raise DevelopmentSupervisorCanaryError(
            "fixed result omits mandatory reported lifecycle flags"
        )
    if result.flags & DevelopmentSupervisorFlag.TERMINATION_SIGNAL_RECEIVED:
        raise DevelopmentSupervisorCanaryError(
            "fixed supervisor received an external termination signal"
        )
    expected_stdout, expected_stderr = _expected_streams(request)
    if (
        result.stdout_observed != len(expected_stdout)
        or result.stderr_observed != len(expected_stderr)
        or result.stdout_sha256 != sha256(expected_stdout).digest()
        or result.stderr_sha256 != sha256(expected_stderr).digest()
    ):
        raise DevelopmentSupervisorCanaryError(
            "fixed scenario stream identity is invalid"
        )
    minimum_reaped = {
        DevelopmentSupervisorScenario.DOUBLE_FORK_SETSID: 3,
        DevelopmentSupervisorScenario.ZOMBIE: 2,
        DevelopmentSupervisorScenario.CPU_FANOUT: 4,
    }.get(request.scenario, 1)
    if result.descendants_reaped < minimum_reaped:
        raise DevelopmentSupervisorCanaryError(
            "fixed scenario reaped too few descendants"
        )
    if result.wall_usec <= 0:
        raise DevelopmentSupervisorCanaryError("fixed scenario wall time is invalid")
    if request.scenario in {
        DevelopmentSupervisorScenario.WALL_TIMEOUT,
        DevelopmentSupervisorScenario.CPU_FANOUT,
    }:
        if (
            result.wall_usec < request.timeout_ms * 1000
            or result.child_exit_code != -1
            or result.child_signal != signal.SIGKILL
        ):
            raise DevelopmentSupervisorCanaryError(
                "timeout scenario termination is invalid"
            )
    elif request.scenario is DevelopmentSupervisorScenario.FORBIDDEN_SYSCALL:
        if result.child_exit_code != -1 or result.child_signal != signal.SIGSYS:
            raise DevelopmentSupervisorCanaryError(
                "forbidden syscall was not killed by seccomp"
            )
    elif request.scenario is DevelopmentSupervisorScenario.STDOUT_FLOOD:
        if (result.child_exit_code, result.child_signal) not in {
            (31, 0),
            (-1, signal.SIGKILL),
        }:
            raise DevelopmentSupervisorCanaryError(
                "stdout overflow termination is invalid"
            )
    elif request.scenario is DevelopmentSupervisorScenario.STDERR_FLOOD:
        if (result.child_exit_code, result.child_signal) not in {
            (32, 0),
            (-1, signal.SIGKILL),
        }:
            raise DevelopmentSupervisorCanaryError(
                "stderr overflow termination is invalid"
            )
    elif result.child_exit_code != 0 or result.child_signal != 0:
        raise DevelopmentSupervisorCanaryError("normal fixed scenario did not exit zero")
    if (
        request.scenario is DevelopmentSupervisorScenario.CPU_FANOUT
        and result.user_cpu_usec + result.sys_cpu_usec <= 0
    ):
        raise DevelopmentSupervisorCanaryError(
            "CPU fan-out reported no descendant CPU usage"
        )


def _scenario_record(
    evidence: DevelopmentSupervisorScenarioEvidence,
    *,
    include_self_digest: bool,
) -> dict[str, object]:
    record: dict[str, object] = {
        "request": evidence.request.to_record(),
        "result": evidence.result.to_record(),
        "request_record_sha256": evidence.request_record_sha256,
        "result_record_sha256": evidence.result_record_sha256,
    }
    if include_self_digest:
        record["scenario_evidence_sha256"] = evidence.scenario_evidence_sha256
    return record


def _compute_scenario_sha256(evidence: DevelopmentSupervisorScenarioEvidence) -> str:
    return sha256(
        canonical_development_runtime_json_bytes(
            _scenario_record(evidence, include_self_digest=False)
        )
    ).hexdigest()


def _validate_scenario_evidence(
    evidence: DevelopmentSupervisorScenarioEvidence,
) -> None:
    if type(evidence.request) is not DevelopmentSupervisorRequest:
        raise DevelopmentSupervisorCanaryError("scenario request type is invalid")
    if type(evidence.result) is not DevelopmentSupervisorResult:
        raise DevelopmentSupervisorCanaryError("scenario result type is invalid")
    validate_development_supervisor_result_binding(
        evidence.result,
        request=evidence.request,
    )
    _validate_fixed_result(evidence.request, evidence.result)
    expected_request_record = sha256(
        canonical_development_supervisor_request_record_bytes(evidence.request)
    ).hexdigest()
    expected_result_record = sha256(
        canonical_development_supervisor_result_record_bytes(evidence.result)
    ).hexdigest()
    if evidence.request_record_sha256 != expected_request_record:
        raise DevelopmentSupervisorCanaryError("request record digest is invalid")
    if evidence.result_record_sha256 != expected_result_record:
        raise DevelopmentSupervisorCanaryError("result record digest is invalid")
    _lower_sha256(evidence.scenario_evidence_sha256, what="scenario_evidence_sha256")
    if evidence.scenario_evidence_sha256 != _compute_scenario_sha256(evidence):
        raise DevelopmentSupervisorCanaryError("scenario evidence digest is invalid")


def _construct_scenario_evidence(
    request: DevelopmentSupervisorRequest,
    result: DevelopmentSupervisorResult,
) -> DevelopmentSupervisorScenarioEvidence:
    request_digest = sha256(
        canonical_development_supervisor_request_record_bytes(request)
    ).hexdigest()
    result_digest = sha256(
        canonical_development_supervisor_result_record_bytes(result)
    ).hexdigest()
    temporary = object.__new__(DevelopmentSupervisorScenarioEvidence)
    object.__setattr__(temporary, "request", request)
    object.__setattr__(temporary, "result", result)
    object.__setattr__(temporary, "request_record_sha256", request_digest)
    object.__setattr__(temporary, "result_record_sha256", result_digest)
    object.__setattr__(temporary, "scenario_evidence_sha256", "0" * 64)
    digest = _compute_scenario_sha256(temporary)
    return DevelopmentSupervisorScenarioEvidence(
        request=request,
        result=result,
        request_record_sha256=request_digest,
        result_record_sha256=result_digest,
        scenario_evidence_sha256=digest,
    )


def _scenario_index_sha256(
    scenarios: tuple[DevelopmentSupervisorScenarioEvidence, ...],
) -> str:
    return sha256(
        canonical_development_runtime_json_bytes(
            [item.to_record() for item in scenarios]
        )
    ).hexdigest()


def _evidence_record(
    evidence: DevelopmentSupervisorCanaryEvidence,
    *,
    include_self_digest: bool,
) -> dict[str, object]:
    record: dict[str, object] = {
        "schema_version": evidence.schema_version,
        "canary_version": evidence.canary_version,
        "kind": evidence.kind,
        "algorithm": evidence.algorithm,
        "native_source_path": evidence.native_source_path,
        "native_source_sha256": evidence.native_source_sha256,
        "compiler_path": evidence.compiler_path,
        "compiler_sha256": evidence.compiler_sha256,
        "compiler_size": evidence.compiler_size,
        "build_contract_argv": list(evidence.build_contract_argv),
        "build_contract_sha256": evidence.build_contract_sha256,
        "supervisor_path": evidence.supervisor_path,
        "supervisor_sha256": evidence.supervisor_sha256,
        "supervisor_size": evidence.supervisor_size,
        "bwrap_path": evidence.bwrap_path,
        "bwrap_sha256": evidence.bwrap_sha256,
        "bwrap_size": evidence.bwrap_size,
        "systemd_run_path": evidence.systemd_run_path,
        "systemd_run_sha256": evidence.systemd_run_sha256,
        "systemd_run_size": evidence.systemd_run_size,
        "systemctl_path": evidence.systemctl_path,
        "systemctl_sha256": evidence.systemctl_sha256,
        "systemctl_size": evidence.systemctl_size,
        "suite_nonce_hex": evidence.suite_nonce_hex,
        "suite_nonce_sha256": evidence.suite_nonce_sha256,
        "launch_contract_argv": list(evidence.launch_contract_argv),
        "launch_contract_sha256": evidence.launch_contract_sha256,
        "scenarios": [item.to_record() for item in evidence.scenarios],
        "scenario_index_sha256": evidence.scenario_index_sha256,
        "runner_injected": evidence.runner_injected,
        "default_runner_invoked": evidence.default_runner_invoked,
    }
    for item in dataclass_fields(DevelopmentSupervisorCanaryEvidence):
        if item.name in record or item.name == "evidence_sha256":
            continue
        record[item.name] = getattr(evidence, item.name)
    if include_self_digest:
        record["evidence_sha256"] = evidence.evidence_sha256
    return record


def _compute_evidence_sha256(evidence: DevelopmentSupervisorCanaryEvidence) -> str:
    return sha256(
        canonical_development_runtime_json_bytes(
            _evidence_record(evidence, include_self_digest=False)
        )
    ).hexdigest()


def _validate_launch_contract(evidence: DevelopmentSupervisorCanaryEvidence) -> None:
    argv = evidence.launch_contract_argv
    if type(argv) is not tuple or any(type(item) is not str for item in argv):
        raise DevelopmentSupervisorCanaryError("launch contract is invalid")
    expected = _normalized_launch_contract(
        build_development_supervisor_systemd_canary_argv(
            controller_pid=12345,
            supervisor_controller_fd=71,
            bwrap_controller_fd=72,
            unit_name=(
                "cbds-supervisor-canary-v1-"
                + "1" * 32
                + "-1.service"
            ),
            systemd_run_path=evidence.systemd_run_path,
        )
    )
    if argv != expected:
        raise DevelopmentSupervisorCanaryError(
            "launch contract differs from the fixed template"
        )
    digest = sha256(canonical_development_runtime_json_bytes(list(argv))).hexdigest()
    if evidence.launch_contract_sha256 != digest:
        raise DevelopmentSupervisorCanaryError("launch contract digest is invalid")


def _validate_evidence(evidence: DevelopmentSupervisorCanaryEvidence) -> None:
    exact: dict[str, object] = {
        "schema_version": DEVELOPMENT_SUPERVISOR_CANARY_SCHEMA_VERSION,
        "canary_version": DEVELOPMENT_SUPERVISOR_CANARY_VERSION,
        "kind": DEVELOPMENT_SUPERVISOR_CANARY_KIND,
        "algorithm": DEVELOPMENT_SUPERVISOR_CANARY_ALGORITHM,
        "candidate_input_api_absent": True,
        "complete_fixed_scenario_vocabulary_used": True,
        "native_source_identity_recorded": True,
        "local_fixed_source_build_reproduced": True,
        "static_supervisor_elf_validated": True,
        "sealed_supervisor_payload_prepared": True,
        "direct_bwrap_pid_namespace_requested": True,
        "systemd_cgroup_envelope_requested": True,
        "exact_result_frames_validated": True,
        "reported_pid1_for_all_scenarios": True,
        "reported_child_security_setup_for_all_scenarios": True,
        "reported_all_descendants_reaped_for_all_scenarios": True,
        "reported_sole_pid1_after_all_scenarios": True,
        "externally_trusted_native_source": False,
        "externally_trusted_supervisor_binary": False,
        "externally_trusted_bwrap": False,
        "externally_trusted_systemd": False,
        "fixed_supervisor_executed_verified": False,
        "trusted_pid1_supervisor_implemented": False,
        "child_seccomp_filter_implemented": False,
        "cumulative_cpu_time_enforced": False,
        "exact_tool_policy_enforced": False,
        "runtime_data_and_dlopen_closure_verified": False,
        "candidate_execution_authorized": False,
        "candidate_executed": False,
        "scored_evaluation_eligible": False,
        "model_selection_eligible": False,
        "claim_pipeline_eligible": False,
    }
    for name, expected in exact.items():
        actual = getattr(evidence, name)
        if type(actual) is not type(expected) or actual != expected:
            raise DevelopmentSupervisorCanaryError(
                f"evidence field {name!r} is invalid"
            )
    if type(evidence.runner_injected) is not bool:
        raise DevelopmentSupervisorCanaryError("runner_injected is invalid")
    if (
        type(evidence.default_runner_invoked) is not bool
        or evidence.default_runner_invoked is evidence.runner_injected
    ):
        raise DevelopmentSupervisorCanaryError("runner provenance is inconsistent")
    for name in (
        "native_source_sha256",
        "compiler_sha256",
        "build_contract_sha256",
        "supervisor_sha256",
        "bwrap_sha256",
        "systemd_run_sha256",
        "systemctl_sha256",
        "suite_nonce_sha256",
        "launch_contract_sha256",
        "scenario_index_sha256",
        "evidence_sha256",
    ):
        _lower_sha256(getattr(evidence, name), what=name)
    for name in (
        "native_source_path",
        "compiler_path",
        "supervisor_path",
        "bwrap_path",
        "systemd_run_path",
        "systemctl_path",
    ):
        _validate_absolute_path(getattr(evidence, name), what=name)
    if evidence.native_source_path != str(_SOURCE_PATH):
        raise DevelopmentSupervisorCanaryError(
            "native_source_path is not the fixed supervisor source"
        )
    for name in (
        "compiler_size",
        "supervisor_size",
        "bwrap_size",
        "systemd_run_size",
        "systemctl_size",
    ):
        value = getattr(evidence, name)
        if type(value) is not int or value <= 0:
            raise DevelopmentSupervisorCanaryError(f"{name} is invalid")
    try:
        resolved_compiler = os.path.realpath(_COMPILER_PATH, strict=True)
    except OSError as exc:
        raise DevelopmentSupervisorCanaryError(
            "fixed compiler path cannot be rebound"
        ) from exc
    if evidence.compiler_path != resolved_compiler:
        raise DevelopmentSupervisorCanaryError("compiler path is not fixed")
    for field, requested in (
        ("systemd_run_path", _SYSTEMD_RUN_PATH),
        ("systemctl_path", _SYSTEMCTL_PATH),
    ):
        try:
            resolved = os.path.realpath(requested, strict=True)
        except OSError as exc:
            raise DevelopmentSupervisorCanaryError(
                f"fixed {field} cannot be rebound"
            ) from exc
        if getattr(evidence, field) != resolved:
            raise DevelopmentSupervisorCanaryError(f"{field} is not fixed")
    if evidence.default_runner_invoked:
        try:
            resolved_bwrap = os.path.realpath(_SYSTEM_BWRAP_PATH, strict=True)
        except OSError as exc:
            raise DevelopmentSupervisorCanaryError(
                "fixed bwrap path cannot be rebound"
            ) from exc
        if evidence.bwrap_path != resolved_bwrap:
            raise DevelopmentSupervisorCanaryError(
                "default runner bwrap_path is not fixed"
            )
    expected_build = (
        evidence.compiler_path,
        *_BUILD_ARGUMENTS,
        f"-ffile-prefix-map=@source-fd={str(_SOURCE_PATH)}",
        "-x",
        "c",
        str(_SOURCE_PATH),
        "-o",
        "@build-output",
    )
    if evidence.build_contract_argv != expected_build:
        raise DevelopmentSupervisorCanaryError(
            "build contract differs from the fixed source build"
        )
    if evidence.build_contract_sha256 != sha256(
        canonical_development_runtime_json_bytes(list(expected_build))
    ).hexdigest():
        raise DevelopmentSupervisorCanaryError("build contract digest is invalid")
    if type(evidence.suite_nonce_hex) is not str:
        raise DevelopmentSupervisorCanaryError("suite_nonce_hex is invalid")
    try:
        suite_nonce = bytes.fromhex(evidence.suite_nonce_hex)
    except ValueError as exc:
        raise DevelopmentSupervisorCanaryError("suite_nonce_hex is invalid") from exc
    if (
        len(suite_nonce) != 32
        or suite_nonce == b"\0" * 32
        or evidence.suite_nonce_hex != suite_nonce.hex()
        or evidence.suite_nonce_sha256 != sha256(suite_nonce).hexdigest()
    ):
        raise DevelopmentSupervisorCanaryError(
            "suite nonce commitment is invalid"
        )
    if (
        type(evidence.scenarios) is not tuple
        or tuple(item.request.scenario for item in evidence.scenarios)
        != DEVELOPMENT_SUPERVISOR_CANARY_SCENARIOS
        or any(
            type(item) is not DevelopmentSupervisorScenarioEvidence
            for item in evidence.scenarios
        )
    ):
        raise DevelopmentSupervisorCanaryError("scenario inventory is not exact")
    for item in evidence.scenarios:
        _validate_scenario_evidence(item)
        expected_request = _fixed_request(item.request.scenario, suite_nonce)
        if item.request != expected_request:
            raise DevelopmentSupervisorCanaryError(
                "scenario request does not derive from the recorded suite nonce"
            )
    if evidence.scenario_index_sha256 != _scenario_index_sha256(evidence.scenarios):
        raise DevelopmentSupervisorCanaryError("scenario index digest is invalid")
    _validate_launch_contract(evidence)
    if evidence.evidence_sha256 != _compute_evidence_sha256(evidence):
        raise DevelopmentSupervisorCanaryError("evidence digest is invalid")


def verify_development_supervisor_canary_evidence(value: object) -> bool:
    """Return whether an exact typed suite-evidence object is valid."""

    if type(value) is not DevelopmentSupervisorCanaryEvidence:
        return False
    try:
        _validate_evidence(value)
    except (
        AttributeError,
        DevelopmentSupervisorCanaryError,
        DevelopmentSupervisorProtocolError,
        OSError,
        TypeError,
        ValueError,
    ):
        return False
    return True


def _construct_evidence(
    *,
    source: _PinnedFile,
    compiler: _PinnedFile,
    build_contract: tuple[str, ...],
    supervisor: _PinnedFile,
    bwrap: _PinnedFile,
    systemd_run: _PinnedFile,
    systemctl: _PinnedFile,
    suite_nonce: bytes,
    launch_contract: tuple[str, ...],
    scenarios: tuple[DevelopmentSupervisorScenarioEvidence, ...],
    runner_injected: bool,
) -> DevelopmentSupervisorCanaryEvidence:
    fields: dict[str, object] = {
        "native_source_path": str(_SOURCE_PATH),
        "native_source_sha256": source.sha256,
        "compiler_path": compiler.path,
        "compiler_sha256": compiler.sha256,
        "compiler_size": compiler.size,
        "build_contract_argv": build_contract,
        "build_contract_sha256": sha256(
            canonical_development_runtime_json_bytes(list(build_contract))
        ).hexdigest(),
        "supervisor_path": supervisor.path,
        "supervisor_sha256": supervisor.sha256,
        "supervisor_size": supervisor.size,
        "bwrap_path": bwrap.path,
        "bwrap_sha256": bwrap.sha256,
        "bwrap_size": bwrap.size,
        "systemd_run_path": systemd_run.path,
        "systemd_run_sha256": systemd_run.sha256,
        "systemd_run_size": systemd_run.size,
        "systemctl_path": systemctl.path,
        "systemctl_sha256": systemctl.sha256,
        "systemctl_size": systemctl.size,
        "suite_nonce_hex": suite_nonce.hex(),
        "suite_nonce_sha256": sha256(suite_nonce).hexdigest(),
        "launch_contract_argv": launch_contract,
        "launch_contract_sha256": sha256(
            canonical_development_runtime_json_bytes(list(launch_contract))
        ).hexdigest(),
        "scenarios": scenarios,
        "scenario_index_sha256": _scenario_index_sha256(scenarios),
        "runner_injected": runner_injected,
        "default_runner_invoked": not runner_injected,
    }
    temporary = object.__new__(DevelopmentSupervisorCanaryEvidence)
    for item in dataclass_fields(DevelopmentSupervisorCanaryEvidence):
        if item.name == "evidence_sha256":
            value: object = "0" * 64
        elif item.name in fields:
            value = fields[item.name]
        elif item.default is not MISSING:
            value = item.default
        else:  # pragma: no cover - required construction table is exhaustive
            raise DevelopmentSupervisorCanaryError(
                f"evidence construction omitted {item.name!r}"
            )
        object.__setattr__(temporary, item.name, value)
    digest = _compute_evidence_sha256(temporary)
    return DevelopmentSupervisorCanaryEvidence(
        evidence_sha256=digest,
        **fields,  # type: ignore[arg-type]
    )


def run_development_supervisor_lifecycle_canary(
    supervisor_executable: str,
    *,
    expected_native_source_sha256: str,
    expected_supervisor_sha256: str,
    bwrap: str = "/usr/bin/bwrap",
    suite_nonce: bytes | None = None,
    runner: SupervisorCanaryRunner | None = None,
) -> DevelopmentSupervisorCanaryEvidence:
    """Run all fixed lifecycle scenarios; never accept or execute a candidate."""

    expected_source_digest = _lower_sha256(
        expected_native_source_sha256,
        what="expected_native_source_sha256",
    )
    expected_digest = _lower_sha256(
        expected_supervisor_sha256,
        what="expected_supervisor_sha256",
    )
    if suite_nonce is None:
        selected_nonce = os.urandom(32)
    else:
        if type(suite_nonce) is not bytes or len(suite_nonce) != 32:
            raise DevelopmentSupervisorCanaryError(
                "suite_nonce must be exact 32-byte bytes"
            )
        selected_nonce = suite_nonce
    if selected_nonce == b"\0" * 32:
        raise DevelopmentSupervisorCanaryError("suite_nonce must not be all zero")

    pinned: list[_PinnedFile] = []
    supervisor_fd: int | None = None
    build_temporary: tempfile.TemporaryDirectory[str] | None = None
    built_supervisor: _PinnedFile | None = None
    try:
        source = _open_pinned_file(
            str(_SOURCE_PATH),
            what="native supervisor source",
            executable=False,
            maximum_bytes=4 * 1024 * 1024,
        )
        pinned.append(source)
        if source.sha256 != expected_source_digest:
            raise DevelopmentSupervisorCanaryError(
                "native supervisor source differs from its caller pin"
            )
        compiler = _open_pinned_file(
            _COMPILER_PATH,
            what="fixed supervisor compiler",
            executable=True,
            maximum_bytes=_MAXIMUM_EXECUTABLE_BYTES,
        )
        pinned.append(compiler)
        supervisor = _open_pinned_file(
            supervisor_executable,
            what="supervisor executable",
            executable=True,
            maximum_bytes=_MAXIMUM_EXECUTABLE_BYTES,
        )
        pinned.append(supervisor)
        if supervisor.sha256 != expected_digest:
            raise DevelopmentSupervisorCanaryError(
                "supervisor executable differs from its caller pin"
            )
        build_temporary, built_supervisor, build_argv = _rebuild_fixed_supervisor(
            source,
            compiler,
        )
        if (
            built_supervisor.sha256 != supervisor.sha256
            or built_supervisor.size != supervisor.size
        ):
            raise DevelopmentSupervisorCanaryError(
                "supervisor executable does not reproduce from the fixed source build"
            )
        build_contract = _normalized_build_contract(build_argv)
        _validate_static_supervisor_elf(supervisor)
        if runner is None and bwrap != _SYSTEM_BWRAP_PATH:
            raise DevelopmentSupervisorCanaryError(
                "default execution requires the fixed system bwrap path"
            )
        pinned_bwrap = _open_pinned_file(
            bwrap,
            what="bwrap",
            executable=True,
            maximum_bytes=_MAXIMUM_EXECUTABLE_BYTES,
        )
        pinned.append(pinned_bwrap)
        pinned_systemd_run = _open_pinned_file(
            _SYSTEMD_RUN_PATH,
            what="systemd-run",
            executable=True,
            maximum_bytes=_MAXIMUM_EXECUTABLE_BYTES,
        )
        pinned.append(pinned_systemd_run)
        pinned_systemctl = _open_pinned_file(
            _SYSTEMCTL_PATH,
            what="systemctl",
            executable=True,
            maximum_bytes=_MAXIMUM_EXECUTABLE_BYTES,
        )
        pinned.append(pinned_systemctl)
        supervisor_fd = _sealed_read_descriptor(supervisor)
        selected_runner = runner if runner is not None else _run_fixed_process
        scenario_evidence: list[DevelopmentSupervisorScenarioEvidence] = []
        unit_token = secrets.token_hex(16)
        launch_contract: tuple[str, ...] | None = None
        for scenario in DEVELOPMENT_SUPERVISOR_CANARY_SCENARIOS:
            try:
                if os.lseek(supervisor_fd, 0, os.SEEK_SET) != 0:
                    raise DevelopmentSupervisorCanaryError(
                        "sealed supervisor descriptor did not rewind"
                    )
            except OSError as exc:
                raise DevelopmentSupervisorCanaryError(
                    "sealed supervisor descriptor cannot be rewound"
                ) from exc
            request = _fixed_request(scenario, selected_nonce)
            frame = encode_development_supervisor_request(request)
            unit_name = (
                "cbds-supervisor-canary-v1-"
                + unit_token
                + f"-{int(scenario)}.service"
            )
            argv = build_development_supervisor_systemd_canary_argv(
                controller_pid=os.getpid(),
                supervisor_controller_fd=supervisor_fd,
                bwrap_controller_fd=pinned_bwrap.descriptor,
                unit_name=unit_name,
                systemd_run_path=pinned_systemd_run.path,
            )
            current_contract = _normalized_launch_contract(argv)
            if launch_contract is None:
                launch_contract = current_contract
            elif current_contract != launch_contract:
                raise DevelopmentSupervisorCanaryError(
                    "fixed scenario launch contracts are inconsistent"
                )
            try:
                process_result = selected_runner(
                    argv,
                    request_frame=frame,
                    request=request,
                    bwrap=pinned_bwrap,
                    supervisor_fd=supervisor_fd,
                    systemd_run=pinned_systemd_run,
                    systemctl=pinned_systemctl,
                    unit_name=unit_name,
                )
            except DevelopmentSupervisorCanaryError:
                raise
            except (
                OSError,
                RuntimeError,
                subprocess.SubprocessError,
                TypeError,
                ValueError,
            ) as exc:
                raise DevelopmentSupervisorCanaryError(
                    "fixed supervisor runner failed closed"
                ) from exc
            if type(process_result) is not DevelopmentSupervisorCanaryProcessResult:
                raise DevelopmentSupervisorCanaryError(
                    "fixed supervisor runner returned the wrong type"
                )
            process_result.__post_init__()
            if process_result.launch_error:
                raise DevelopmentSupervisorCanaryError(
                    f"fixed supervisor namespace could not launch {scenario.name.lower()}"
                )
            if process_result.timed_out:
                raise DevelopmentSupervisorCanaryError(
                    "outer fixed supervisor runner timed out"
                )
            if process_result.output_truncated:
                raise DevelopmentSupervisorCanaryError(
                    "outer fixed supervisor result exceeded its bound"
                )
            if process_result.returncode != 0:
                raise DevelopmentSupervisorCanaryError(
                    "fixed supervisor namespace returned nonzero for "
                    + scenario.name.lower()
                )
            if process_result.stderr:
                raise DevelopmentSupervisorCanaryError(
                    "fixed supervisor namespace emitted outer stderr"
                )
            result = parse_development_supervisor_result(
                process_result.stdout,
                request=request,
            )
            _validate_fixed_result(request, result)
            scenario_evidence.append(_construct_scenario_evidence(request, result))

        for value, name in (
            (source, "native supervisor source"),
            (compiler, "fixed supervisor compiler"),
            (supervisor, "supervisor executable"),
            (built_supervisor, "rebuilt supervisor executable"),
            (pinned_bwrap, "bwrap"),
            (pinned_systemd_run, "systemd-run"),
            (pinned_systemctl, "systemctl"),
        ):
            _verify_pinned_file(value, what=name)
        if launch_contract is None:
            raise DevelopmentSupervisorCanaryError("launch contract is missing")
        return _construct_evidence(
            source=source,
            compiler=compiler,
            build_contract=build_contract,
            supervisor=supervisor,
            bwrap=pinned_bwrap,
            systemd_run=pinned_systemd_run,
            systemctl=pinned_systemctl,
            suite_nonce=selected_nonce,
            launch_contract=launch_contract,
            scenarios=tuple(scenario_evidence),
            runner_injected=runner is not None,
        )
    except (DevelopmentSupervisorCanaryError, DevelopmentSupervisorProtocolError):
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise DevelopmentSupervisorCanaryError(
            "fixed supervisor lifecycle canary failed closed"
        ) from exc
    finally:
        if supervisor_fd is not None:
            try:
                os.close(supervisor_fd)
            except OSError:
                pass
        if built_supervisor is not None:
            try:
                os.close(built_supervisor.descriptor)
            except OSError:
                pass
        if build_temporary is not None:
            build_temporary.cleanup()
        while pinned:
            value = pinned.pop()
            try:
                os.close(value.descriptor)
            except OSError:
                pass


__all__ = [
    "DEVELOPMENT_SUPERVISOR_CANARY_ALGORITHM",
    "DEVELOPMENT_SUPERVISOR_CANARY_KIND",
    "DEVELOPMENT_SUPERVISOR_CANARY_PATH",
    "DEVELOPMENT_SUPERVISOR_CANARY_SCHEMA_VERSION",
    "DEVELOPMENT_SUPERVISOR_CANARY_SCENARIOS",
    "DEVELOPMENT_SUPERVISOR_CANARY_VERSION",
    "DevelopmentSupervisorCanaryError",
    "DevelopmentSupervisorCanaryEvidence",
    "DevelopmentSupervisorCanaryProcessResult",
    "DevelopmentSupervisorScenarioEvidence",
    "build_development_supervisor_canary_argv",
    "build_development_supervisor_systemd_canary_argv",
    "run_development_supervisor_lifecycle_canary",
    "verify_development_supervisor_canary_evidence",
]
