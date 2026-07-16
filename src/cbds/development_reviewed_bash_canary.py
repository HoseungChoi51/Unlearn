"""One fixed, reviewed Bash execution canary for development integration.

The public execution entry point accepts only an optional nonce and no caller-
selected program, command, argv, fixture, runtime, verifier, or score.  It
reconstructs the single source-reviewed fixture, program, runtime and policy
owned by the adjacent ``development_reviewed_bash_*`` modules, builds the
fixed repository-native supervisor, and launches exactly that case in a
rootless systemd/Bubblewrap envelope.

Service activation descriptors 3, 4 and 5 are deliberately unused by
Bubblewrap and reach the native PID1 supervisor as the reviewed program,
fixture-identity token and writable workspace-snapshot sink.  A second program
descriptor, beginning the mount-only descriptor range at 6, projects the same
sealed bytes at ``/cbds-program.sh``.  No mutable runtime source path enters
the namespace.

Successful evidence means only that this one reviewed program was observed in
the fixed local development envelope and that its output passed the trusted
fixture verifier.  It never means a synthesized candidate was executed or
authorized.  Runtime-data/dlopen closure, external binary trust, a general
Bash seccomp policy, exact utility enforcement, scored evaluation, model
selection and research claims remain explicitly false.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import MISSING, dataclass, fields as dataclass_fields
import fcntl
from hashlib import sha256
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import stat
import subprocess
import tempfile
from time import monotonic
from typing import Final

from .development_candidate_protocol import (
    DEVELOPMENT_CANDIDATE_CLEANUP_FLAGS,
    DEVELOPMENT_CANDIDATE_RESULT_BYTES,
    DEVELOPMENT_CANDIDATE_SETUP_FLAGS,
    DevelopmentCandidateFlag,
    DevelopmentCandidateOutcome,
    DevelopmentCandidateProcessStatus,
    DevelopmentCandidateProtocolError,
    DevelopmentCandidateRequest,
    DevelopmentCandidateResult,
    canonical_development_candidate_request_record_bytes,
    canonical_development_candidate_result_record_bytes,
    encode_development_candidate_request,
    parse_development_candidate_result,
    validate_development_candidate_result_binding,
)
from .development_candidate_workspace_snapshot import (
    DevelopmentCandidateWorkspaceComparison,
    DevelopmentCandidateWorkspaceSnapshot,
    DevelopmentCandidateWorkspaceSnapshotError,
    compare_development_candidate_workspace_snapshot_to_handle,
    parse_development_candidate_workspace_snapshot,
)
from .development_reviewed_bash_fixture import (
    FROZEN_REVIEWED_BASH_PROGRAM,
    FROZEN_REVIEWED_CASE_SHA256,
    FROZEN_REVIEWED_EXTERNAL_COMMANDS,
    FROZEN_REVIEWED_FIXTURE_DEFINITION_SHA256,
    FROZEN_REVIEWED_INVOCATION_SHA256,
    FROZEN_REVIEWED_PROGRAM_SHA256,
    DevelopmentReviewedBashFixtureCase,
    build_development_reviewed_bash_fixture_case,
    materialize_development_reviewed_bash_fixture,
    validate_development_reviewed_bash_fixture_case,
)
from .development_reviewed_bash_policy import (
    DEVELOPMENT_REVIEWED_BASH_CPU_TIME_LIMIT_USEC,
    DEVELOPMENT_REVIEWED_BASH_LAUNCHER_FSIZE_MAX_BYTES,
    DEVELOPMENT_REVIEWED_BASH_GID,
    DEVELOPMENT_REVIEWED_BASH_HOSTNAME,
    DEVELOPMENT_REVIEWED_BASH_MEMORY_MAX_BYTES,
    DEVELOPMENT_REVIEWED_BASH_NOFILE_MAX,
    DEVELOPMENT_REVIEWED_BASH_PROGRAM_PATH,
    DEVELOPMENT_REVIEWED_BASH_STDERR_CAP_BYTES,
    DEVELOPMENT_REVIEWED_BASH_STDOUT_CAP_BYTES,
    DEVELOPMENT_REVIEWED_BASH_SUPERVISOR_PATH,
    DEVELOPMENT_REVIEWED_BASH_TASKS_MAX,
    DEVELOPMENT_REVIEWED_BASH_TMPFS_BYTES,
    DEVELOPMENT_REVIEWED_BASH_UID,
    DEVELOPMENT_REVIEWED_BASH_WALL_TIMEOUT_USEC,
    DEVELOPMENT_REVIEWED_BASH_WORKSPACE_PATH,
    DEVELOPMENT_REVIEWED_BASH_WORKSPACE_SNAPSHOT_CAP_BYTES,
    canonical_development_reviewed_bash_policy_bytes,
    development_reviewed_bash_policy_sha256,
)
from .development_reviewed_bash_runtime import (
    FROZEN_REVIEWED_BASH_RUNTIME_MANIFEST_SHA256,
    FROZEN_REVIEWED_BASH_RUNTIME_PROJECTION_SHA256,
    DevelopmentReviewedBashRuntimeCase,
    materialize_development_reviewed_bash_runtime,
    validate_development_reviewed_bash_runtime_case,
)
from .development_runtime_bundle import canonical_development_runtime_json_bytes
from .development_supervisor_canary import (
    DevelopmentSupervisorCanaryError,
    _PinnedFile,
    _clean_environment,
    _open_pinned_file,
    _sealed_read_descriptor,
    _validate_static_supervisor_elf,
    _verify_pinned_file,
)
from .executable_fixture_verifier import (
    FixtureVerificationEvidence,
    validate_fixture_verification_evidence_binding,
    verify_executable_fixture,
)
from .executable_workspace import WorkspaceHandle


DEVELOPMENT_REVIEWED_BASH_CANARY_SCHEMA_VERSION: Final[str] = "1.0.0"
DEVELOPMENT_REVIEWED_BASH_CANARY_VERSION: Final[str] = "1.0.0"
DEVELOPMENT_REVIEWED_BASH_CANARY_KIND: Final[str] = (
    "cbds-development-reviewed-bash-execution-canary"
)
DEVELOPMENT_REVIEWED_BASH_CANARY_ALGORITHM: Final[str] = (
    "fixed-reviewed-case-systemd-openfile-bwrap-native-pid1-v1"
)

DEVELOPMENT_REVIEWED_BASH_NATIVE_SOURCE_SHA256: Final[str] = (
    "71e2cde89002e6e23dc86f024088e0d2022cbf260bd1637667b12f602409d9dc"
)
DEVELOPMENT_REVIEWED_BASH_FIXTURE_IDENTITY_PATH: Final[str] = (
    "/cbds-fixture.identity"
)
DEVELOPMENT_REVIEWED_BASH_WORKSPACE_SNAPSHOT_PATH: Final[str] = (
    "/cbds-workspace.snapshot"
)
DEVELOPMENT_REVIEWED_BASH_NATIVE_PROGRAM_FD: Final[int] = 3
DEVELOPMENT_REVIEWED_BASH_NATIVE_FIXTURE_IDENTITY_FD: Final[int] = 4
DEVELOPMENT_REVIEWED_BASH_NATIVE_WORKSPACE_SNAPSHOT_FD: Final[int] = 5
DEVELOPMENT_REVIEWED_BASH_MOUNT_FD_START: Final[int] = 6

_SOURCE_PATH: Final[Path] = (
    Path(__file__).resolve().parents[2]
    / "native"
    / "cbds-development-candidate-supervisor.c"
)
_COMPILER_PATH: Final[str] = "/usr/bin/gcc"
_BWRAP_PATH: Final[str] = "/usr/bin/bwrap"
_SYSTEMD_RUN_PATH: Final[str] = "/usr/bin/systemd-run"
_SYSTEMCTL_PATH: Final[str] = "/usr/bin/systemctl"
_BUILD_ARGUMENTS: Final[tuple[str, ...]] = (
    "-std=gnu17",
    "-O2",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-static-pie",
    "-Wl,-z,relro,-z,now,-z,noexecstack",
)
_MAXIMUM_EXECUTABLE_BYTES: Final[int] = 32 * 1024 * 1024
_OUTER_STDERR_BYTES: Final[int] = 4096
_OUTER_TIMEOUT_SECONDS: Final[float] = 5.0
_UNIT_RE: Final[re.Pattern[str]] = re.compile(
    r"cbds-reviewed-bash-canary-v1-[0-9a-f]{32}\.service"
)
_EMPTY_SHA256: Final[bytes] = sha256(b"").digest()


class DevelopmentReviewedBashCanaryError(ValueError):
    """Raised whenever the fixed development canary fails closed."""


@dataclass(frozen=True, slots=True)
class DevelopmentReviewedBashCanaryProcessResult:
    """Bounded outer observation returned by the fixed launch runner."""

    returncode: int | None
    stdout: bytes = b""
    stderr: bytes = b""
    workspace_snapshot: bytes = b""
    timed_out: bool = False
    output_truncated: bool = False
    launch_error: bool = False

    def __post_init__(self) -> None:
        if self.returncode is not None and type(self.returncode) is not int:
            raise TypeError("returncode must be an exact integer or None")
        for name in ("stdout", "stderr", "workspace_snapshot"):
            if type(getattr(self, name)) is not bytes:
                raise TypeError(f"{name} must be immutable bytes")
        for name in ("timed_out", "output_truncated", "launch_error"):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be an exact boolean")


_ReviewedBashCanaryRunner = Callable[..., DevelopmentReviewedBashCanaryProcessResult]


@dataclass(frozen=True, slots=True)
class DevelopmentReviewedBashCanaryEvidence:
    """Raw-payload-byte-free, nonconfidential evidence for one fixed run.

    Paths, modes, sizes, and payload digests remain visible.  This public-
    development record is not safe for reuse across a sealed boundary.
    """

    fixture_case_sha256: str
    runtime_case_sha256: str
    runtime_snapshot_sha256: str
    policy_sha256: str
    allowed_tools_sha256: str
    workspace_baseline_sha256: str
    request: DevelopmentCandidateRequest
    result: DevelopmentCandidateResult
    workspace_snapshot: DevelopmentCandidateWorkspaceSnapshot
    workspace_comparison: DevelopmentCandidateWorkspaceComparison
    fixture_verification: FixtureVerificationEvidence
    native_source_path: str
    native_source_sha256: str
    compiler_path: str
    compiler_sha256: str
    supervisor_sha256: str
    bwrap_path: str
    bwrap_sha256: str
    systemd_run_path: str
    systemd_run_sha256: str
    systemctl_path: str
    systemctl_sha256: str
    build_contract_argv: tuple[str, ...]
    build_contract_sha256: str
    launch_contract_argv: tuple[str, ...]
    launch_contract_sha256: str
    unit_name: str
    runner_injected: bool
    default_runner_invoked: bool
    reviewed_program_executed: bool
    evidence_sha256: str
    schema_version: str = DEVELOPMENT_REVIEWED_BASH_CANARY_SCHEMA_VERSION
    canary_version: str = DEVELOPMENT_REVIEWED_BASH_CANARY_VERSION
    kind: str = DEVELOPMENT_REVIEWED_BASH_CANARY_KIND
    algorithm: str = DEVELOPMENT_REVIEWED_BASH_CANARY_ALGORITHM
    fixed_reviewed_case_reconstructed: bool = True
    native_result_bound_to_request: bool = True
    workspace_snapshot_bound_to_native_result: bool = True
    systemd_cgroup_quiescence_verified: bool = True
    workspace_snapshot_sealed_after_quiescence: bool = True
    post_quiescence_input_baseline_revalidated: bool = True
    output_projection_compared: bool = True
    fixture_functionally_verified: bool = True
    candidate_input_api_absent: bool = True
    runtime_data_and_dlopen_closure_verified: bool = False
    externally_trusted_native_source: bool = False
    externally_trusted_supervisor: bool = False
    externally_trusted_runtime: bool = False
    externally_trusted_bwrap: bool = False
    externally_trusted_systemd: bool = False
    general_bash_seccomp_policy_verified: bool = False
    exact_tool_policy_enforced: bool = False
    production_cumulative_cpu_enforcement_verified: bool = False
    candidate_execution_authorized: bool = False
    candidate_executed: bool = False
    scored_evaluation_eligible: bool = False
    model_selection_eligible: bool = False
    claim_pipeline_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        _validate_evidence(self)

    def to_record(self) -> dict[str, object]:
        _validate_evidence(self)
        return _evidence_record(self, include_self_digest=True)


def _canonical(value: object) -> bytes:
    return canonical_development_runtime_json_bytes(value)


def _allowed_tools_sha256(fixture: DevelopmentReviewedBashFixtureCase) -> str:
    validate_development_reviewed_bash_fixture_case(fixture)
    value = fixture.invocation.to_audit_record().get("allowed_tools_sha256")
    expected = "3b6cde893e5ee2b88984d3ccb1cc4283430c2fc244eda61940ab4c8b949175f0"
    if type(value) is not str or value != expected:
        raise DevelopmentReviewedBashCanaryError(
            "reviewed invocation allowed-tools identity drifted"
        )
    return value


def _unit_name(value: object) -> str:
    if type(value) is not str or _UNIT_RE.fullmatch(value) is None:
        raise DevelopmentReviewedBashCanaryError("canary unit name is invalid")
    return value


def _run_unit_systemctl(
    systemctl: _PinnedFile,
    arguments: tuple[str, ...],
    *,
    capture: bool,
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            (systemctl.path, "--user", *arguments),
            executable=f"/proc/self/fd/{systemctl.descriptor}",
            pass_fds=(systemctl.descriptor,),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.PIPE if capture else subprocess.DEVNULL,
            shell=False,
            close_fds=True,
            env=_clean_environment(),
            timeout=1.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, TypeError, ValueError) as exc:
        raise DevelopmentReviewedBashCanaryError(
            "transient reviewed Bash unit control failed"
        ) from exc
    return completed


def _stop_and_verify_unit(systemctl: _PinnedFile, unit_name: str) -> None:
    _unit_name(unit_name)
    for arguments in (
        ("kill", "--kill-who=all", "--signal=SIGKILL", unit_name),
        ("stop", unit_name),
    ):
        try:
            _run_unit_systemctl(systemctl, arguments, capture=False)
        except DevelopmentReviewedBashCanaryError:
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
        raise DevelopmentReviewedBashCanaryError(
            "transient reviewed Bash unit quiescence cannot be verified"
        )
    try:
        lines = completed.stdout.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise DevelopmentReviewedBashCanaryError(
            "transient reviewed Bash unit state is invalid"
        ) from exc
    properties: dict[str, str] = {}
    allowed = {"LoadState", "ActiveState", "SubState", "ControlGroup"}
    for line in lines:
        name, separator, value = line.partition("=")
        if not separator or name not in allowed or name in properties:
            raise DevelopmentReviewedBashCanaryError(
                "transient reviewed Bash unit state is invalid"
            )
        properties[name] = value
    if (
        properties.get("LoadState") not in {"loaded", "not-found"}
        or properties.get("ActiveState") != "inactive"
        or properties.get("SubState") != "dead"
        or properties.get("ControlGroup") != ""
        or set(properties) != allowed
    ):
        raise DevelopmentReviewedBashCanaryError(
            "transient reviewed Bash unit is not inactive and quiescent"
        )


def _terminate_and_reap(
    process: subprocess.Popen[bytes],
    *,
    systemctl: _PinnedFile,
    unit_name: str,
) -> None:
    unit_error: DevelopmentReviewedBashCanaryError | None = None
    try:
        _stop_and_verify_unit(systemctl, unit_name)
    except DevelopmentReviewedBashCanaryError as exc:
        unit_error = exc
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError, PermissionError):
            try:
                process.kill()
            except OSError:
                pass
    try:
        process.wait(timeout=1.0)
    except (OSError, subprocess.TimeoutExpired) as exc:
        try:
            process.kill()
            process.wait(timeout=1.0)
        except (OSError, subprocess.TimeoutExpired) as final:
            raise DevelopmentReviewedBashCanaryError(
                "outer reviewed Bash process could not be reaped"
            ) from final
        if unit_error is None:
            unit_error = DevelopmentReviewedBashCanaryError(
                "outer reviewed Bash process required repeated reaping"
            )
    if unit_error is not None:
        raise unit_error


def _descriptor_table(values: tuple[int, ...], *, expected: int, label: str) -> None:
    if (
        type(values) is not tuple
        or len(values) != expected
        or any(type(value) is not int or value < 3 for value in values)
        or len(set(values)) != len(values)
    ):
        raise DevelopmentReviewedBashCanaryError(
            f"{label} descriptor table is invalid"
        )


def _openfile_property(
    controller_pid: int,
    descriptor: int,
    name: str,
    mode: str,
) -> str:
    if mode not in {"read-only", "truncate"}:
        raise DevelopmentReviewedBashCanaryError("OpenFile mode is invalid")
    return (
        f"OpenFile=/proc/{controller_pid}/fd/{descriptor}:"
        f"{name}:{mode}"
    )


def build_development_reviewed_bash_canary_argv(
    runtime: DevelopmentReviewedBashRuntimeCase,
    *,
    controller_pid: int,
    program_controller_fd: int,
    fixture_identity_controller_fd: int,
    workspace_snapshot_controller_fd: int,
    program_projection_controller_fd: int,
    workspace_controller_fd: int,
    runtime_controller_fds: tuple[int, ...],
    supervisor_controller_fd: int,
    bwrap_controller_fd: int,
    unit_name: str,
    systemd_run_path: str = _SYSTEMD_RUN_PATH,
) -> tuple[str, ...]:
    """Build the exact one-case launch argv; no command input exists."""

    validate_development_reviewed_bash_runtime_case(runtime)
    if runtime.closed:
        raise DevelopmentReviewedBashCanaryError("reviewed runtime is closed")
    if type(controller_pid) is not int or controller_pid <= 1:
        raise DevelopmentReviewedBashCanaryError("controller_pid is invalid")
    _unit_name(unit_name)
    if systemd_run_path != _SYSTEMD_RUN_PATH:
        raise DevelopmentReviewedBashCanaryError("systemd-run path is not fixed")
    fixed_descriptors = (
        program_controller_fd,
        fixture_identity_controller_fd,
        workspace_snapshot_controller_fd,
        program_projection_controller_fd,
        workspace_controller_fd,
        supervisor_controller_fd,
        bwrap_controller_fd,
    )
    _descriptor_table(fixed_descriptors, expected=7, label="fixed launch")
    _descriptor_table(
        runtime_controller_fds,
        expected=len(runtime.regular_slots),
        label="runtime",
    )
    if set(fixed_descriptors) & set(runtime_controller_fds):
        raise DevelopmentReviewedBashCanaryError(
            "fixed and runtime descriptors alias"
        )
    oversized_runtime_slots = tuple(
        slot.destination_path
        for slot in runtime.regular_slots
        if slot.size > DEVELOPMENT_REVIEWED_BASH_LAUNCHER_FSIZE_MAX_BYTES
    )
    if oversized_runtime_slots:
        raise DevelopmentReviewedBashCanaryError(
            "frozen runtime payload exceeds the launcher file-size envelope"
        )

    runtime_fd_start = DEVELOPMENT_REVIEWED_BASH_MOUNT_FD_START + 2
    supervisor_service_fd = runtime_fd_start + len(runtime.regular_slots)
    properties = (
        f"MemoryMax={DEVELOPMENT_REVIEWED_BASH_MEMORY_MAX_BYTES}",
        "MemorySwapMax=0",
        f"TasksMax={DEVELOPMENT_REVIEWED_BASH_TASKS_MAX}",
        "CPUQuota=100%",
        f"LimitNOFILE={DEVELOPMENT_REVIEWED_BASH_NOFILE_MAX}",
        "LimitCORE=0",
        f"LimitFSIZE={DEVELOPMENT_REVIEWED_BASH_LAUNCHER_FSIZE_MAX_BYTES}",
        "RuntimeMaxSec=5s",
        "TimeoutStopSec=1s",
        "KillMode=control-group",
        "SendSIGKILL=yes",
        "OOMPolicy=kill",
        "NoNewPrivileges=yes",
        "RestrictAddressFamilies=AF_UNIX AF_NETLINK",
        "UMask=0077",
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
    openfiles = (
        _openfile_property(
            controller_pid,
            program_controller_fd,
            "cbds-reviewed-program-native",
            "read-only",
        ),
        _openfile_property(
            controller_pid,
            fixture_identity_controller_fd,
            "cbds-reviewed-fixture-identity",
            "read-only",
        ),
        _openfile_property(
            controller_pid,
            workspace_snapshot_controller_fd,
            "cbds-reviewed-workspace-snapshot",
            "truncate",
        ),
        _openfile_property(
            controller_pid,
            program_projection_controller_fd,
            "cbds-reviewed-program-projection",
            "read-only",
        ),
        _openfile_property(
            controller_pid,
            workspace_controller_fd,
            "cbds-reviewed-workspace",
            "read-only",
        ),
        *(
            _openfile_property(
                controller_pid,
                descriptor,
                slot.slot_id,
                "read-only",
            )
            for descriptor, slot in zip(
                runtime_controller_fds,
                runtime.regular_slots,
                strict=True,
            )
        ),
        _openfile_property(
            controller_pid,
            supervisor_controller_fd,
            "cbds-reviewed-bash-supervisor",
            "read-only",
        ),
    )
    for value in openfiles:
        argv.extend(("--property", value))

    argv.extend(
        (
            f"/proc/{controller_pid}/fd/{bwrap_controller_fd}",
            "--unshare-all",
            "--unshare-user",
            "--uid",
            str(DEVELOPMENT_REVIEWED_BASH_UID),
            "--gid",
            str(DEVELOPMENT_REVIEWED_BASH_GID),
            "--hostname",
            DEVELOPMENT_REVIEWED_BASH_HOSTNAME,
            "--disable-userns",
            "--assert-userns-disabled",
            "--die-with-parent",
            "--new-session",
            "--as-pid-1",
            "--clearenv",
        )
    )
    for directory in runtime.directories:
        if directory.destination_path != "/":
            argv.extend(("--dir", directory.destination_path))
    argv.extend(
        (
            "--perms",
            "0444",
            "--ro-bind-data",
            str(DEVELOPMENT_REVIEWED_BASH_MOUNT_FD_START),
            DEVELOPMENT_REVIEWED_BASH_PROGRAM_PATH,
            "--bind-fd",
            str(DEVELOPMENT_REVIEWED_BASH_MOUNT_FD_START + 1),
            DEVELOPMENT_REVIEWED_BASH_WORKSPACE_PATH,
        )
    )
    for index, slot in enumerate(runtime.regular_slots):
        argv.extend(
            (
                "--perms",
                f"{slot.materialized_mode:04o}",
                "--ro-bind-data",
                str(runtime_fd_start + index),
                slot.destination_path,
            )
        )
    for entry in runtime.entries:
        if entry.kind == "symlink":
            if entry.symlink_target is None:
                raise DevelopmentReviewedBashCanaryError(
                    "runtime symlink target is missing"
                )
            argv.extend(
                ("--symlink", entry.symlink_target, entry.destination_path)
            )
    argv.extend(
        (
            "--perms",
            "0555",
            "--ro-bind-data",
            str(supervisor_service_fd),
            DEVELOPMENT_REVIEWED_BASH_SUPERVISOR_PATH,
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--size",
            str(DEVELOPMENT_REVIEWED_BASH_TMPFS_BYTES),
            "--tmpfs",
            "/tmp",
            "--chmod",
            "01777",
            "/tmp",
            "--cap-drop",
            "ALL",
            "--setenv",
            "HOME",
            "/nonexistent",
            "--setenv",
            "LANG",
            "C",
            "--setenv",
            "LC_ALL",
            "C",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "SHELL",
            "/usr/bin/bash",
            "--setenv",
            "TZ",
            "UTC",
            "--chmod",
            "0555",
            "/",
            "--remount-ro",
            "/",
            "--chdir",
            DEVELOPMENT_REVIEWED_BASH_WORKSPACE_PATH,
            DEVELOPMENT_REVIEWED_BASH_SUPERVISOR_PATH,
        )
    )
    return tuple(argv)


def _fixed_request(
    fixture: DevelopmentReviewedBashFixtureCase,
    runtime: DevelopmentReviewedBashRuntimeCase,
    workspace: WorkspaceHandle,
    nonce: bytes,
) -> DevelopmentCandidateRequest:
    validate_development_reviewed_bash_fixture_case(fixture)
    validate_development_reviewed_bash_runtime_case(runtime)
    if type(workspace) is not WorkspaceHandle or workspace.closed:
        raise DevelopmentReviewedBashCanaryError("workspace handle is invalid")
    if type(nonce) is not bytes or len(nonce) != 32 or nonce == b"\0" * 32:
        raise DevelopmentReviewedBashCanaryError("nonce must be nonzero 32-byte bytes")
    return DevelopmentCandidateRequest(
        program_bytes=len(FROZEN_REVIEWED_BASH_PROGRAM),
        wall_timeout_usec=DEVELOPMENT_REVIEWED_BASH_WALL_TIMEOUT_USEC,
        cpu_time_limit_usec=DEVELOPMENT_REVIEWED_BASH_CPU_TIME_LIMIT_USEC,
        stdout_cap_bytes=DEVELOPMENT_REVIEWED_BASH_STDOUT_CAP_BYTES,
        stderr_cap_bytes=DEVELOPMENT_REVIEWED_BASH_STDERR_CAP_BYTES,
        workspace_snapshot_cap_bytes=(
            DEVELOPMENT_REVIEWED_BASH_WORKSPACE_SNAPSHOT_CAP_BYTES
        ),
        nonce=nonce,
        invocation_sha256=bytes.fromhex(FROZEN_REVIEWED_INVOCATION_SHA256),
        program_sha256=bytes.fromhex(FROZEN_REVIEWED_PROGRAM_SHA256),
        fixture_definition_sha256=bytes.fromhex(
            FROZEN_REVIEWED_FIXTURE_DEFINITION_SHA256
        ),
        workspace_baseline_sha256=bytes.fromhex(
            workspace.baseline.baseline_sha256
        ),
        runtime_snapshot_sha256=bytes.fromhex(runtime.snapshot_sha256),
        allowed_tools_sha256=bytes.fromhex(_allowed_tools_sha256(fixture)),
        policy_sha256=bytes.fromhex(development_reviewed_bash_policy_sha256()),
    )


def _required_seals() -> int:
    result = 0
    for name in (
        "F_SEAL_SEAL",
        "F_SEAL_SHRINK",
        "F_SEAL_GROW",
        "F_SEAL_WRITE",
    ):
        value = getattr(fcntl, name, None)
        if type(value) is not int or value < 0:
            raise DevelopmentReviewedBashCanaryError(
                f"required seal primitive {name} is unavailable"
            )
        result |= value
    return result


def _sealed_bytes(payload: bytes, *, name: str, mode: int) -> int:
    if (
        type(payload) is not bytes
        or not payload
        or type(name) is not str
        or not name
        or type(mode) is not int
        or mode not in {0o444, 0o555}
    ):
        raise DevelopmentReviewedBashCanaryError(
            "sealed fixed payload parameters are invalid"
        )
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
        raise DevelopmentReviewedBashCanaryError(
            "sealed memfd primitives are unavailable"
        )
    writable: int | None = None
    readable: int | None = None
    try:
        writable = creator(name, cloexec | allow_sealing)
        view = memoryview(payload)
        while view:
            amount = os.write(writable, view)
            if amount <= 0:
                raise DevelopmentReviewedBashCanaryError(
                    "sealed fixed payload copy made no progress"
                )
            view = view[amount:]
        os.fchmod(writable, mode)
        fcntl.fcntl(writable, add_seals, _required_seals())
        readable = os.open(
            f"/proc/self/fd/{writable}",
            os.O_RDONLY | os.O_CLOEXEC,
        )
        metadata = os.fstat(readable)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_size != len(payload)
            or fcntl.fcntl(readable, get_seals) != _required_seals()
            or os.get_inheritable(readable)
            or os.pread(readable, len(payload) + 1, 0) != payload
        ):
            raise DevelopmentReviewedBashCanaryError(
                "sealed fixed payload differs from its source"
            )
        result = readable
        readable = None
        return result
    except DevelopmentReviewedBashCanaryError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise DevelopmentReviewedBashCanaryError(
            "cannot seal a fixed canary payload"
        ) from exc
    finally:
        if readable is not None:
            os.close(readable)
        if writable is not None:
            os.close(writable)


def _workspace_snapshot_sink() -> int:
    creator = getattr(os, "memfd_create", None)
    cloexec = getattr(os, "MFD_CLOEXEC", None)
    allow_sealing = getattr(os, "MFD_ALLOW_SEALING", None)
    if (
        not callable(creator)
        or type(cloexec) is not int
        or type(allow_sealing) is not int
    ):
        raise DevelopmentReviewedBashCanaryError("memfd_create is unavailable")
    try:
        descriptor = creator(
            "cbds-reviewed-workspace-snapshot",
            cloexec | allow_sealing,
        )
        os.fchmod(descriptor, 0o600)
        if os.get_inheritable(descriptor):
            raise DevelopmentReviewedBashCanaryError(
                "workspace snapshot sink is inheritable"
            )
        return descriptor
    except DevelopmentReviewedBashCanaryError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise DevelopmentReviewedBashCanaryError(
            "cannot create workspace snapshot sink"
        ) from exc


def _rebuild_fixed_supervisor(
    source: _PinnedFile,
    compiler: _PinnedFile,
) -> tuple[tempfile.TemporaryDirectory[str], _PinnedFile, tuple[str, ...]]:
    temporary = tempfile.TemporaryDirectory(
        prefix="cbds-reviewed-bash-supervisor-build-"
    )
    output = Path(temporary.name) / "cbds-reviewed-bash-supervisor"
    source_fd_path = f"/proc/self/fd/{source.descriptor}"
    argv = (
        compiler.path,
        *_BUILD_ARGUMENTS,
        f"-ffile-prefix-map={source_fd_path}={str(_SOURCE_PATH)}",
        "-x",
        "c",
        source_fd_path,
        "-o",
        str(output),
    )
    built: _PinnedFile | None = None
    try:
        completed = subprocess.run(
            argv,
            executable=f"/proc/self/fd/{compiler.descriptor}",
            pass_fds=(source.descriptor, compiler.descriptor),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            close_fds=True,
            start_new_session=True,
            env=_clean_environment(),
            timeout=30.0,
            check=False,
        )
        if completed.returncode != 0:
            raise DevelopmentReviewedBashCanaryError(
                "fixed native supervisor build returned nonzero"
            )
        output.chmod(0o555)
        built = _open_pinned_file(
            str(output),
            what="rebuilt reviewed Bash supervisor",
            executable=True,
            maximum_bytes=_MAXIMUM_EXECUTABLE_BYTES,
        )
        _verify_pinned_file(source, what="reviewed Bash native source")
        _verify_pinned_file(compiler, what="reviewed Bash compiler")
        return temporary, built, argv
    except DevelopmentReviewedBashCanaryError:
        if built is not None:
            os.close(built.descriptor)
        temporary.cleanup()
        raise
    except (
        DevelopmentSupervisorCanaryError,
        OSError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as exc:
        if built is not None:
            os.close(built.descriptor)
        temporary.cleanup()
        raise DevelopmentReviewedBashCanaryError(
            "cannot reproduce the fixed native supervisor"
        ) from exc


def _normalized_build_argv(argv: tuple[str, ...]) -> tuple[str, ...]:
    if (
        type(argv) is not tuple
        or not argv
        or any(type(item) is not str for item in argv)
    ):
        raise DevelopmentReviewedBashCanaryError("fixed build argv is invalid")
    expected_prefix = (argv[0], *_BUILD_ARGUMENTS)
    if (
        len(argv) != len(expected_prefix) + 6
        or argv[: len(expected_prefix)] != expected_prefix
        or argv[-6]
        != f"-ffile-prefix-map={argv[-3]}={str(_SOURCE_PATH)}"
        or argv[-5:-3] != ("-x", "c")
        or re.fullmatch(r"/proc/self/fd/[0-9]+", argv[-3]) is None
        or argv[-2] != "-o"
    ):
        raise DevelopmentReviewedBashCanaryError("fixed build argv is invalid")
    return (
        *expected_prefix,
        f"-ffile-prefix-map=@source-fd={str(_SOURCE_PATH)}",
        "-x",
        "c",
        str(_SOURCE_PATH),
        "-o",
        "@build-output",
    )


def _read_snapshot_sink(descriptor: int) -> bytes:
    try:
        before = os.fstat(descriptor)
        maximum = DEVELOPMENT_REVIEWED_BASH_WORKSPACE_SNAPSHOT_CAP_BYTES + 1
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 0
            or before.st_size > maximum
        ):
            raise DevelopmentReviewedBashCanaryError(
                "workspace snapshot sink length is outside its exact bound"
            )
        first = os.pread(descriptor, before.st_size + 1, 0)
        middle = os.fstat(descriptor)
        second = os.pread(descriptor, before.st_size + 1, 0)
        if (
            len(first) != before.st_size
            or first != second
            or (before.st_dev, before.st_ino, before.st_size)
            != (middle.st_dev, middle.st_ino, middle.st_size)
        ):
            raise DevelopmentReviewedBashCanaryError(
                "workspace snapshot sink changed while being read"
            )
        add_seals = getattr(fcntl, "F_ADD_SEALS", None)
        get_seals = getattr(fcntl, "F_GET_SEALS", None)
        if type(add_seals) is not int or type(get_seals) is not int:
            raise DevelopmentReviewedBashCanaryError(
                "workspace snapshot sealing primitives are unavailable"
            )
        fcntl.fcntl(descriptor, add_seals, _required_seals())
        after = os.fstat(descriptor)
        if (
            fcntl.fcntl(descriptor, get_seals) != _required_seals()
            or (middle.st_dev, middle.st_ino, middle.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or os.pread(descriptor, after.st_size + 1, 0) != first
        ):
            raise DevelopmentReviewedBashCanaryError(
                "workspace snapshot sink changed across final sealing"
            )
        return first
    except DevelopmentReviewedBashCanaryError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise DevelopmentReviewedBashCanaryError(
            "workspace snapshot sink cannot be read"
        ) from exc


def _run_fixed_process(
    argv: tuple[str, ...],
    *,
    request_frame: bytes,
    request: DevelopmentCandidateRequest,
    snapshot_fd: int,
    systemd_run: _PinnedFile,
    systemctl: _PinnedFile,
    unit_name: str,
    **_fixed_context: object,
) -> DevelopmentReviewedBashCanaryProcessResult:
    """Run one fixed launch with bounded post-capture validation."""

    if (
        type(argv) is not tuple
        or request_frame != encode_development_candidate_request(request)
        or type(snapshot_fd) is not int
        or snapshot_fd < 3
        or unit_name not in argv
        and f"--unit={unit_name}" not in argv
    ):
        raise DevelopmentReviewedBashCanaryError(
            "default runner received a noncanonical fixed launch"
        )
    process: subprocess.Popen[bytes] | None = None
    killed = False
    selector: selectors.BaseSelector | None = None
    streams: dict[int, tuple[str, object]] = {}
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    caps = {
        "stdout": DEVELOPMENT_CANDIDATE_RESULT_BYTES,
        "stderr": _OUTER_STDERR_BYTES,
    }
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
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise DevelopmentReviewedBashCanaryError(
                "default runner pipes are unavailable"
            )
        try:
            process.stdin.write(request_frame)
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
        selector = selectors.DefaultSelector()
        for descriptor, (_name, stream) in streams.items():
            os.set_blocking(descriptor, False)
            selector.register(stream, selectors.EVENT_READ, descriptor)
        deadline = monotonic() + _OUTER_TIMEOUT_SECONDS
        truncated = False
        timed_out = False
        while selector.get_map():
            remaining = deadline - monotonic()
            if remaining <= 0:
                timed_out = True
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
                    try:
                        stream.close()  # type: ignore[attr-defined]
                    except OSError:
                        pass
                    continue
                if len(block) > available:
                    buffers[name].extend(block[:available])
                    truncated = True
                    break
                buffers[name].extend(block)
            if truncated:
                break
        if timed_out or truncated:
            _terminate_and_reap(
                process,
                systemctl=systemctl,
                unit_name=unit_name,
            )
            killed = True
            return DevelopmentReviewedBashCanaryProcessResult(
                returncode=process.returncode,
                stdout=bytes(buffers["stdout"]),
                stderr=bytes(buffers["stderr"]),
                timed_out=timed_out,
                output_truncated=truncated,
            )
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            _terminate_and_reap(
                process,
                systemctl=systemctl,
                unit_name=unit_name,
            )
            killed = True
            return DevelopmentReviewedBashCanaryProcessResult(
                returncode=process.returncode,
                stdout=bytes(buffers["stdout"]),
                stderr=bytes(buffers["stderr"]),
                timed_out=True,
            )
        _stop_and_verify_unit(systemctl, unit_name)
        return DevelopmentReviewedBashCanaryProcessResult(
            returncode=process.returncode,
            stdout=bytes(buffers["stdout"]),
            stderr=bytes(buffers["stderr"]),
            workspace_snapshot=_read_snapshot_sink(snapshot_fd),
        )
    except DevelopmentReviewedBashCanaryError:
        if process is not None:
            try:
                _terminate_and_reap(
                    process,
                    systemctl=systemctl,
                    unit_name=unit_name,
                )
            finally:
                killed = True
        raise
    except (
        DevelopmentSupervisorCanaryError,
        OSError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ):
        if process is not None:
            try:
                _terminate_and_reap(
                    process,
                    systemctl=systemctl,
                    unit_name=unit_name,
                )
            finally:
                killed = True
        return DevelopmentReviewedBashCanaryProcessResult(
            returncode=None,
            launch_error=True,
        )
    finally:
        if selector is not None:
            try:
                selector.close()
            except OSError:
                pass
        for _name, stream in streams.values():
            try:
                stream.close()  # type: ignore[attr-defined]
            except OSError:
                pass
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
        if process is not None and not killed and process.poll() is None:
            _terminate_and_reap(
                process,
                systemctl=systemctl,
                unit_name=unit_name,
            )


def _normalized_launch_argv(argv: tuple[str, ...]) -> tuple[str, ...]:
    if type(argv) is not tuple or any(type(item) is not str for item in argv):
        raise DevelopmentReviewedBashCanaryError("launch argv is invalid")
    result = list(argv)
    unit_indexes = [
        index for index, value in enumerate(result) if value.startswith("--unit=")
    ]
    if len(unit_indexes) != 1:
        raise DevelopmentReviewedBashCanaryError(
            "launch argv has an invalid unit inventory"
        )
    _unit_name(result[unit_indexes[0]].removeprefix("--unit="))
    result[unit_indexes[0]] = "--unit=@unit"

    pattern = re.compile(
        r"OpenFile=/proc/([1-9][0-9]*)/fd/([0-9]+):"
        r"([A-Za-z0-9_.-]+):(read-only|truncate)"
    )
    controller_pid: str | None = None
    for index, value in enumerate(result):
        match = pattern.fullmatch(value)
        if match is None:
            continue
        if int(match.group(2)) < 3:
            raise DevelopmentReviewedBashCanaryError(
                "launch OpenFile descriptor is invalid"
            )
        if controller_pid is None:
            controller_pid = match.group(1)
        elif controller_pid != match.group(1):
            raise DevelopmentReviewedBashCanaryError(
                "launch OpenFile controller identities differ"
            )
        result[index] = (
            f"OpenFile=@controller-fd:{match.group(3)}:{match.group(4)}"
        )
    if controller_pid is None:
        raise DevelopmentReviewedBashCanaryError("launch has no OpenFile bindings")
    try:
        bwrap_index = result.index("--unshare-all") - 1
    except ValueError as exc:
        raise DevelopmentReviewedBashCanaryError(
            "launch omits the Bubblewrap namespace"
        ) from exc
    bwrap_match = re.fullmatch(
        r"/proc/([1-9][0-9]*)/fd/([0-9]+)", result[bwrap_index]
    )
    if (
        bwrap_match is None
        or bwrap_match.group(1) != controller_pid
        or int(bwrap_match.group(2)) < 3
    ):
        raise DevelopmentReviewedBashCanaryError(
            "launch Bubblewrap descriptor identity is invalid"
        )
    result[bwrap_index] = "@controller-bwrap-fd"
    if any(re.search(r"/proc/[1-9][0-9]*/fd/[0-9]+", item) for item in result):
        raise DevelopmentReviewedBashCanaryError(
            "normalized launch retained a controller descriptor"
        )
    return tuple(result)


def _expected_normalized_launch_contract() -> tuple[str, ...]:
    """Rebuild the complete fixed launch shape from the pinned runtime."""

    try:
        with tempfile.TemporaryDirectory(
            prefix="cbds-reviewed-bash-contract-validation-"
        ) as temporary:
            with materialize_development_reviewed_bash_runtime(
                Path(temporary) / "runtime"
            ) as runtime:
                runtime_fds = tuple(
                    range(100, 100 + len(runtime.regular_slots))
                )
                argv = build_development_reviewed_bash_canary_argv(
                    runtime,
                    controller_pid=12345,
                    program_controller_fd=71,
                    fixture_identity_controller_fd=72,
                    workspace_snapshot_controller_fd=73,
                    program_projection_controller_fd=74,
                    workspace_controller_fd=75,
                    runtime_controller_fds=runtime_fds,
                    supervisor_controller_fd=76,
                    bwrap_controller_fd=77,
                    unit_name=(
                        "cbds-reviewed-bash-canary-v1-"
                        + "1" * 32
                        + ".service"
                    ),
                )
                return _normalized_launch_argv(argv)
    except DevelopmentReviewedBashCanaryError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise DevelopmentReviewedBashCanaryError(
            "cannot rebuild the exact normalized launch contract"
        ) from exc


def _validate_normalized_launch_contract(argv: object) -> None:
    if (
        type(argv) is not tuple
        or not argv
        or any(type(item) is not str for item in argv)
        or argv != _expected_normalized_launch_contract()
    ):
        raise DevelopmentReviewedBashCanaryError(
            "recorded launch differs from the complete fixed contract"
        )


def _fixed_result_is_success(
    request: DevelopmentCandidateRequest,
    result: DevelopmentCandidateResult,
) -> None:
    validate_development_candidate_result_binding(result, request=request)
    required = (
        DEVELOPMENT_CANDIDATE_SETUP_FLAGS
        | DEVELOPMENT_CANDIDATE_CLEANUP_FLAGS
        | DevelopmentCandidateFlag.WORKSPACE_SNAPSHOT_WRITTEN
    )
    controller_only = (
        DevelopmentCandidateFlag.RUNTIME_SNAPSHOT_VALIDATED
        | DevelopmentCandidateFlag.WORKSPACE_BASELINE_VALIDATED
        | DevelopmentCandidateFlag.ALLOWED_TOOLS_VALIDATED
        | DevelopmentCandidateFlag.POLICY_VALIDATED
    )
    if (
        result.outcome is not DevelopmentCandidateOutcome.NORMAL
        or result.process_status is not DevelopmentCandidateProcessStatus.EXITED
        or result.child_exit_code != 0
        or result.child_signal != 0
        or result.flags & required != required
        or result.flags & controller_only
        or result.flags & (
            DevelopmentCandidateFlag.STDOUT_OVERFLOW
            | DevelopmentCandidateFlag.STDERR_OVERFLOW
            | DevelopmentCandidateFlag.WALL_LIMIT_REACHED
            | DevelopmentCandidateFlag.CPU_LIMIT_REACHED
            | DevelopmentCandidateFlag.WORKSPACE_SNAPSHOT_OVERFLOW
        )
        or result.stdout_observed != 0
        or result.stderr_observed != 0
        or result.stdout_sha256 != _EMPTY_SHA256
        or result.stderr_sha256 != _EMPTY_SHA256
        or result.wall_usec <= 0
    ):
        raise DevelopmentReviewedBashCanaryError(
            "native result does not describe the fixed successful case"
        )


def _evidence_record(
    evidence: DevelopmentReviewedBashCanaryEvidence,
    *,
    include_self_digest: bool,
) -> dict[str, object]:
    record: dict[str, object] = {
        "fixture_case_sha256": evidence.fixture_case_sha256,
        "runtime_case_sha256": evidence.runtime_case_sha256,
        "runtime_snapshot_sha256": evidence.runtime_snapshot_sha256,
        "runtime_manifest_sha256": FROZEN_REVIEWED_BASH_RUNTIME_MANIFEST_SHA256,
        "runtime_projection_sha256": FROZEN_REVIEWED_BASH_RUNTIME_PROJECTION_SHA256,
        "policy_sha256": evidence.policy_sha256,
        "allowed_tools_sha256": evidence.allowed_tools_sha256,
        "workspace_baseline_sha256": evidence.workspace_baseline_sha256,
        "request": evidence.request.to_record(),
        "request_record_sha256": sha256(
            canonical_development_candidate_request_record_bytes(evidence.request)
        ).hexdigest(),
        "result": evidence.result.to_record(),
        "result_record_sha256": sha256(
            canonical_development_candidate_result_record_bytes(evidence.result)
        ).hexdigest(),
        "workspace_snapshot": evidence.workspace_snapshot.to_answer_free_record(),
        "workspace_comparison": evidence.workspace_comparison.to_record(),
        "fixture_verification": evidence.fixture_verification.to_record(),
        "native_source_path": evidence.native_source_path,
        "native_source_sha256": evidence.native_source_sha256,
        "compiler_path": evidence.compiler_path,
        "compiler_sha256": evidence.compiler_sha256,
        "supervisor_sha256": evidence.supervisor_sha256,
        "bwrap_path": evidence.bwrap_path,
        "bwrap_sha256": evidence.bwrap_sha256,
        "systemd_run_path": evidence.systemd_run_path,
        "systemd_run_sha256": evidence.systemd_run_sha256,
        "systemctl_path": evidence.systemctl_path,
        "systemctl_sha256": evidence.systemctl_sha256,
        "build_contract_argv": list(evidence.build_contract_argv),
        "build_contract_sha256": evidence.build_contract_sha256,
        "launch_contract_argv": list(evidence.launch_contract_argv),
        "launch_contract_sha256": evidence.launch_contract_sha256,
        "unit_name": evidence.unit_name,
        "runner_injected": evidence.runner_injected,
        "default_runner_invoked": evidence.default_runner_invoked,
        "reviewed_program_executed": evidence.reviewed_program_executed,
    }
    for item in dataclass_fields(DevelopmentReviewedBashCanaryEvidence):
        if item.name in record or item.name == "evidence_sha256":
            continue
        record[item.name] = getattr(evidence, item.name)
    if include_self_digest:
        record["evidence_sha256"] = evidence.evidence_sha256
    return record


def _compute_evidence_sha256(
    evidence: DevelopmentReviewedBashCanaryEvidence,
) -> str:
    return sha256(
        _canonical(_evidence_record(evidence, include_self_digest=False))
    ).hexdigest()


def _lower_sha256(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DevelopmentReviewedBashCanaryError(
            f"{label} must be lowercase SHA-256"
        )
    return value


def _validate_evidence(evidence: DevelopmentReviewedBashCanaryEvidence) -> None:
    if type(evidence) is not DevelopmentReviewedBashCanaryEvidence:
        raise DevelopmentReviewedBashCanaryError("evidence type is invalid")
    exact: dict[str, object] = {
        "schema_version": DEVELOPMENT_REVIEWED_BASH_CANARY_SCHEMA_VERSION,
        "canary_version": DEVELOPMENT_REVIEWED_BASH_CANARY_VERSION,
        "kind": DEVELOPMENT_REVIEWED_BASH_CANARY_KIND,
        "algorithm": DEVELOPMENT_REVIEWED_BASH_CANARY_ALGORITHM,
        "fixture_case_sha256": FROZEN_REVIEWED_CASE_SHA256,
        "native_source_path": str(_SOURCE_PATH),
        "native_source_sha256": DEVELOPMENT_REVIEWED_BASH_NATIVE_SOURCE_SHA256,
        "policy_sha256": development_reviewed_bash_policy_sha256(),
        "allowed_tools_sha256": (
            "3b6cde893e5ee2b88984d3ccb1cc4283430c2fc244eda61940ab4c8b949175f0"
        ),
        "fixed_reviewed_case_reconstructed": True,
        "native_result_bound_to_request": True,
        "workspace_snapshot_bound_to_native_result": True,
        "output_projection_compared": True,
        "fixture_functionally_verified": True,
        "candidate_input_api_absent": True,
        "runner_injected": False,
        "default_runner_invoked": True,
        "reviewed_program_executed": True,
        "systemd_cgroup_quiescence_verified": True,
        "workspace_snapshot_sealed_after_quiescence": True,
        "post_quiescence_input_baseline_revalidated": True,
        "runtime_data_and_dlopen_closure_verified": False,
        "externally_trusted_native_source": False,
        "externally_trusted_supervisor": False,
        "externally_trusted_runtime": False,
        "externally_trusted_bwrap": False,
        "externally_trusted_systemd": False,
        "general_bash_seccomp_policy_verified": False,
        "exact_tool_policy_enforced": False,
        "production_cumulative_cpu_enforcement_verified": False,
        "candidate_execution_authorized": False,
        "candidate_executed": False,
        "scored_evaluation_eligible": False,
        "model_selection_eligible": False,
        "claim_pipeline_eligible": False,
        "claim_authorized": False,
    }
    for name, expected in exact.items():
        observed = getattr(evidence, name)
        if type(observed) is not type(expected) or observed != expected:
            raise DevelopmentReviewedBashCanaryError(
                f"evidence field {name!r} is invalid"
            )
    for name in (
        "runtime_case_sha256",
        "runtime_snapshot_sha256",
        "workspace_baseline_sha256",
        "compiler_sha256",
        "supervisor_sha256",
        "bwrap_sha256",
        "systemd_run_sha256",
        "systemctl_sha256",
        "build_contract_sha256",
        "launch_contract_sha256",
        "evidence_sha256",
    ):
        _lower_sha256(getattr(evidence, name), name)
    if type(evidence.request) is not DevelopmentCandidateRequest:
        raise DevelopmentReviewedBashCanaryError("request type is invalid")
    if type(evidence.result) is not DevelopmentCandidateResult:
        raise DevelopmentReviewedBashCanaryError("result type is invalid")
    _fixed_result_is_success(evidence.request, evidence.result)
    if (
        evidence.request.program_bytes != len(FROZEN_REVIEWED_BASH_PROGRAM)
        or evidence.request.wall_timeout_usec
        != DEVELOPMENT_REVIEWED_BASH_WALL_TIMEOUT_USEC
        or evidence.request.cpu_time_limit_usec
        != DEVELOPMENT_REVIEWED_BASH_CPU_TIME_LIMIT_USEC
        or evidence.request.stdout_cap_bytes
        != DEVELOPMENT_REVIEWED_BASH_STDOUT_CAP_BYTES
        or evidence.request.stderr_cap_bytes
        != DEVELOPMENT_REVIEWED_BASH_STDERR_CAP_BYTES
        or evidence.request.workspace_snapshot_cap_bytes
        != DEVELOPMENT_REVIEWED_BASH_WORKSPACE_SNAPSHOT_CAP_BYTES
        or evidence.request.invocation_sha256.hex()
        != FROZEN_REVIEWED_INVOCATION_SHA256
        or evidence.request.program_sha256.hex() != FROZEN_REVIEWED_PROGRAM_SHA256
        or evidence.request.fixture_definition_sha256.hex()
        != FROZEN_REVIEWED_FIXTURE_DEFINITION_SHA256
        or evidence.request.runtime_snapshot_sha256.hex()
        != evidence.runtime_snapshot_sha256
        or evidence.request.workspace_baseline_sha256.hex()
        != evidence.workspace_baseline_sha256
        or evidence.request.allowed_tools_sha256.hex()
        != evidence.allowed_tools_sha256
        or evidence.request.policy_sha256.hex() != evidence.policy_sha256
    ):
        raise DevelopmentReviewedBashCanaryError(
            "request differs from the fixed evidence identities"
        )
    if type(evidence.workspace_snapshot) is not DevelopmentCandidateWorkspaceSnapshot:
        raise DevelopmentReviewedBashCanaryError("workspace snapshot type is invalid")
    evidence.workspace_snapshot.__post_init__()
    if (
        evidence.result.workspace_snapshot_bytes
        != evidence.workspace_snapshot.archive_bytes
        or evidence.result.workspace_snapshot_sha256.hex()
        != evidence.workspace_snapshot.archive_sha256
    ):
        raise DevelopmentReviewedBashCanaryError(
            "parsed workspace snapshot is not bound to the native result"
        )
    if type(evidence.workspace_comparison) is not DevelopmentCandidateWorkspaceComparison:
        raise DevelopmentReviewedBashCanaryError("workspace comparison type is invalid")
    evidence.workspace_comparison.__post_init__()
    if (
        evidence.workspace_comparison.snapshot_archive_sha256
        != evidence.workspace_snapshot.archive_sha256
        or evidence.workspace_comparison.workspace_baseline_sha256
        != evidence.workspace_baseline_sha256
    ):
        raise DevelopmentReviewedBashCanaryError(
            "workspace comparison is not bound to the snapshot and baseline"
        )
    if type(evidence.fixture_verification) is not FixtureVerificationEvidence:
        raise DevelopmentReviewedBashCanaryError("fixture verification type is invalid")
    evidence.fixture_verification.__post_init__()
    if (
        evidence.fixture_verification.passed is not True
        or evidence.fixture_verification.workspace_baseline_sha256
        != evidence.workspace_baseline_sha256
        or evidence.fixture_verification.input_tree_sha256
        != evidence.workspace_comparison.input_tree_sha256
        or evidence.fixture_verification.output_tree_sha256
        != evidence.workspace_comparison.output_tree_sha256
    ):
        raise DevelopmentReviewedBashCanaryError(
            "fixture verification is not the post-quiescence workspace result"
        )
    _unit_name(evidence.unit_name)
    try:
        fixed_paths = {
            "compiler_path": os.path.realpath(_COMPILER_PATH, strict=True),
            "bwrap_path": os.path.realpath(_BWRAP_PATH, strict=True),
            "systemd_run_path": os.path.realpath(_SYSTEMD_RUN_PATH, strict=True),
            "systemctl_path": os.path.realpath(_SYSTEMCTL_PATH, strict=True),
        }
    except OSError as exc:
        raise DevelopmentReviewedBashCanaryError(
            "fixed launcher path cannot be rebound"
        ) from exc
    for name, expected in fixed_paths.items():
        if getattr(evidence, name) != expected:
            raise DevelopmentReviewedBashCanaryError(
                f"evidence {name!r} is not the fixed launcher path"
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
    if (
        type(evidence.build_contract_argv) is not tuple
        or any(type(item) is not str for item in evidence.build_contract_argv)
        or evidence.build_contract_argv != expected_build
        or evidence.build_contract_argv[0] != evidence.compiler_path
        or evidence.build_contract_sha256
        != sha256(_canonical(list(evidence.build_contract_argv))).hexdigest()
        or type(evidence.launch_contract_argv) is not tuple
        or not evidence.launch_contract_argv
        or any(type(item) is not str for item in evidence.launch_contract_argv)
        or evidence.launch_contract_sha256
        != sha256(_canonical(list(evidence.launch_contract_argv))).hexdigest()
    ):
        raise DevelopmentReviewedBashCanaryError(
            "recorded build or launch digest is invalid"
        )
    _validate_normalized_launch_contract(evidence.launch_contract_argv)
    if evidence.evidence_sha256 != _compute_evidence_sha256(evidence):
        raise DevelopmentReviewedBashCanaryError("evidence digest is invalid")


def verify_development_reviewed_bash_canary_evidence(value: object) -> bool:
    if type(value) is not DevelopmentReviewedBashCanaryEvidence:
        return False
    try:
        _validate_evidence(value)
    except (
        AttributeError,
        DevelopmentCandidateProtocolError,
        DevelopmentCandidateWorkspaceSnapshotError,
        DevelopmentReviewedBashCanaryError,
        OSError,
        TypeError,
        ValueError,
    ):
        return False
    return True


def _construct_evidence(
    *,
    fixture: DevelopmentReviewedBashFixtureCase,
    runtime: DevelopmentReviewedBashRuntimeCase,
    request: DevelopmentCandidateRequest,
    result: DevelopmentCandidateResult,
    snapshot: DevelopmentCandidateWorkspaceSnapshot,
    comparison: DevelopmentCandidateWorkspaceComparison,
    verification: FixtureVerificationEvidence,
    source: _PinnedFile,
    compiler: _PinnedFile,
    supervisor: _PinnedFile,
    bwrap: _PinnedFile,
    systemd_run: _PinnedFile,
    systemctl: _PinnedFile,
    build_contract: tuple[str, ...],
    launch_contract: tuple[str, ...],
    unit_name: str,
) -> DevelopmentReviewedBashCanaryEvidence:
    values: dict[str, object] = {
        "fixture_case_sha256": fixture.case_sha256,
        "runtime_case_sha256": runtime.case_sha256,
        "runtime_snapshot_sha256": runtime.snapshot_sha256,
        "policy_sha256": development_reviewed_bash_policy_sha256(),
        "allowed_tools_sha256": _allowed_tools_sha256(fixture),
        "workspace_baseline_sha256": request.workspace_baseline_sha256.hex(),
        "request": request,
        "result": result,
        "workspace_snapshot": snapshot,
        "workspace_comparison": comparison,
        "fixture_verification": verification,
        "native_source_path": str(_SOURCE_PATH),
        "native_source_sha256": source.sha256,
        "compiler_path": compiler.path,
        "compiler_sha256": compiler.sha256,
        "supervisor_sha256": supervisor.sha256,
        "bwrap_path": bwrap.path,
        "bwrap_sha256": bwrap.sha256,
        "systemd_run_path": systemd_run.path,
        "systemd_run_sha256": systemd_run.sha256,
        "systemctl_path": systemctl.path,
        "systemctl_sha256": systemctl.sha256,
        "build_contract_argv": build_contract,
        "build_contract_sha256": sha256(
            _canonical(list(build_contract))
        ).hexdigest(),
        "launch_contract_argv": launch_contract,
        "launch_contract_sha256": sha256(
            _canonical(list(launch_contract))
        ).hexdigest(),
        "unit_name": unit_name,
        "runner_injected": False,
        "default_runner_invoked": True,
        "reviewed_program_executed": True,
        "systemd_cgroup_quiescence_verified": True,
        "workspace_snapshot_sealed_after_quiescence": True,
        "post_quiescence_input_baseline_revalidated": True,
    }
    temporary = object.__new__(DevelopmentReviewedBashCanaryEvidence)
    for item in dataclass_fields(DevelopmentReviewedBashCanaryEvidence):
        if item.name == "evidence_sha256":
            value: object = "0" * 64
        elif item.name in values:
            value = values[item.name]
        elif item.default is not MISSING:
            value = item.default
        else:  # pragma: no cover - construction table is exhaustive
            raise DevelopmentReviewedBashCanaryError(
                f"evidence construction omitted {item.name!r}"
            )
        object.__setattr__(temporary, item.name, value)
    digest = _compute_evidence_sha256(temporary)
    return DevelopmentReviewedBashCanaryEvidence(
        evidence_sha256=digest,
        **values,  # type: ignore[arg-type]
    )


def _run_development_reviewed_bash_canary_impl(
    *,
    nonce: bytes | None = None,
    runner: _ReviewedBashCanaryRunner,
    export_evidence: bool,
) -> DevelopmentReviewedBashCanaryEvidence | None:
    """Internal implementation shared with a permanently nonexporting test seam."""

    selected_nonce = os.urandom(32) if nonce is None else nonce
    if (
        type(selected_nonce) is not bytes
        or len(selected_nonce) != 32
        or selected_nonce == b"\0" * 32
    ):
        raise DevelopmentReviewedBashCanaryError(
            "nonce must be nonzero exact 32-byte bytes"
        )
    if not callable(runner) or type(export_evidence) is not bool:
        raise DevelopmentReviewedBashCanaryError(
            "internal runner configuration is invalid"
        )
    if export_evidence and runner is not _run_fixed_process:
        raise DevelopmentReviewedBashCanaryError(
            "only the built-in runner may export canary evidence"
        )

    pinned: list[_PinnedFile] = []
    owned_descriptors: list[int] = []
    build_temporary: tempfile.TemporaryDirectory[str] | None = None
    built_supervisor: _PinnedFile | None = None
    try:
        with tempfile.TemporaryDirectory(
            prefix="cbds-reviewed-bash-canary-"
        ) as temporary:
            root = Path(temporary)
            fixture = build_development_reviewed_bash_fixture_case()
            with materialize_development_reviewed_bash_fixture(
                fixture,
                root / "workspace",
            ) as workspace, materialize_development_reviewed_bash_runtime(
                root / "runtime"
            ) as runtime:
                source = _open_pinned_file(
                    str(_SOURCE_PATH),
                    what="reviewed Bash native source",
                    executable=False,
                    maximum_bytes=4 * 1024 * 1024,
                )
                pinned.append(source)
                if source.sha256 != DEVELOPMENT_REVIEWED_BASH_NATIVE_SOURCE_SHA256:
                    raise DevelopmentReviewedBashCanaryError(
                        "reviewed Bash native source differs from its frozen digest"
                    )
                compiler = _open_pinned_file(
                    _COMPILER_PATH,
                    what="reviewed Bash compiler",
                    executable=True,
                    maximum_bytes=_MAXIMUM_EXECUTABLE_BYTES,
                )
                pinned.append(compiler)
                build_temporary, built_supervisor, build_argv = (
                    _rebuild_fixed_supervisor(source, compiler)
                )
                _validate_static_supervisor_elf(built_supervisor)
                if (
                    built_supervisor.size
                    > DEVELOPMENT_REVIEWED_BASH_LAUNCHER_FSIZE_MAX_BYTES
                    or len(FROZEN_REVIEWED_BASH_PROGRAM)
                    > DEVELOPMENT_REVIEWED_BASH_LAUNCHER_FSIZE_MAX_BYTES
                ):
                    raise DevelopmentReviewedBashCanaryError(
                        "fixed projected payload exceeds the launcher "
                        "file-size envelope"
                    )
                build_contract = _normalized_build_argv(build_argv)
                pinned_bwrap = _open_pinned_file(
                    _BWRAP_PATH,
                    what="reviewed Bash bwrap",
                    executable=True,
                    maximum_bytes=_MAXIMUM_EXECUTABLE_BYTES,
                )
                pinned.append(pinned_bwrap)
                pinned_systemd_run = _open_pinned_file(
                    _SYSTEMD_RUN_PATH,
                    what="reviewed Bash systemd-run",
                    executable=True,
                    maximum_bytes=_MAXIMUM_EXECUTABLE_BYTES,
                )
                pinned.append(pinned_systemd_run)
                pinned_systemctl = _open_pinned_file(
                    _SYSTEMCTL_PATH,
                    what="reviewed Bash systemctl",
                    executable=True,
                    maximum_bytes=_MAXIMUM_EXECUTABLE_BYTES,
                )
                pinned.append(pinned_systemctl)

                program_native_fd = _sealed_bytes(
                    FROZEN_REVIEWED_BASH_PROGRAM,
                    name="cbds-reviewed-program-native",
                    mode=0o444,
                )
                owned_descriptors.append(program_native_fd)
                program_projection_fd = os.dup(program_native_fd)
                os.set_inheritable(program_projection_fd, False)
                owned_descriptors.append(program_projection_fd)
                fixture_identity_fd = _sealed_bytes(
                    bytes.fromhex(FROZEN_REVIEWED_FIXTURE_DEFINITION_SHA256),
                    name="cbds-reviewed-fixture-identity",
                    mode=0o444,
                )
                owned_descriptors.append(fixture_identity_fd)
                snapshot_fd = _workspace_snapshot_sink()
                owned_descriptors.append(snapshot_fd)
                workspace_fd = workspace.duplicate_launch_directory()
                owned_descriptors.append(workspace_fd)
                runtime_fd_list: list[int] = []
                for slot in runtime.regular_slots:
                    descriptor = runtime.duplicate_regular_fd(
                        slot.destination_path
                    )
                    owned_descriptors.append(descriptor)
                    runtime_fd_list.append(descriptor)
                runtime_fds = tuple(runtime_fd_list)
                supervisor_fd = _sealed_read_descriptor(built_supervisor)
                owned_descriptors.append(supervisor_fd)

                request = _fixed_request(
                    fixture,
                    runtime,
                    workspace,
                    selected_nonce,
                )
                request_frame = encode_development_candidate_request(request)
                unit_name = (
                    "cbds-reviewed-bash-canary-v1-"
                    + secrets.token_hex(16)
                    + ".service"
                )
                argv = build_development_reviewed_bash_canary_argv(
                    runtime,
                    controller_pid=os.getpid(),
                    program_controller_fd=program_native_fd,
                    fixture_identity_controller_fd=fixture_identity_fd,
                    workspace_snapshot_controller_fd=snapshot_fd,
                    program_projection_controller_fd=program_projection_fd,
                    workspace_controller_fd=workspace_fd,
                    runtime_controller_fds=runtime_fds,
                    supervisor_controller_fd=supervisor_fd,
                    bwrap_controller_fd=pinned_bwrap.descriptor,
                    unit_name=unit_name,
                )
                launch_contract = _normalized_launch_argv(argv)
                try:
                    process_result = runner(
                        argv,
                        request_frame=request_frame,
                        request=request,
                        snapshot_fd=snapshot_fd,
                        systemd_run=pinned_systemd_run,
                        systemctl=pinned_systemctl,
                        unit_name=unit_name,
                        workspace_handle=workspace,
                        fixture_case=fixture,
                    )
                except DevelopmentReviewedBashCanaryError:
                    raise
                except (
                    OSError,
                    RuntimeError,
                    subprocess.SubprocessError,
                    TypeError,
                    ValueError,
                ) as exc:
                    raise DevelopmentReviewedBashCanaryError(
                        "fixed reviewed Bash runner failed closed"
                    ) from exc
                if type(process_result) is not DevelopmentReviewedBashCanaryProcessResult:
                    raise DevelopmentReviewedBashCanaryError(
                        "fixed runner returned the wrong type"
                    )
                process_result.__post_init__()
                if process_result.launch_error:
                    raise DevelopmentReviewedBashCanaryError(
                        "fixed reviewed Bash namespace could not launch"
                    )
                if process_result.timed_out:
                    raise DevelopmentReviewedBashCanaryError(
                        "outer fixed reviewed Bash runner timed out"
                    )
                if process_result.output_truncated:
                    raise DevelopmentReviewedBashCanaryError(
                        "outer fixed reviewed Bash output exceeded its bound"
                    )
                if process_result.returncode != 0 or process_result.stderr:
                    raise DevelopmentReviewedBashCanaryError(
                        "fixed reviewed Bash namespace returned invalid outer status"
                    )
                result = parse_development_candidate_result(
                    process_result.stdout,
                    request=request,
                )
                _fixed_result_is_success(request, result)
                raw_snapshot = process_result.workspace_snapshot
                if (
                    len(raw_snapshot) != result.workspace_snapshot_bytes
                    or sha256(raw_snapshot).digest()
                    != result.workspace_snapshot_sha256
                ):
                    raise DevelopmentReviewedBashCanaryError(
                        "snapshot sink bytes do not bind the native result"
                    )
                snapshot = parse_development_candidate_workspace_snapshot(
                    raw_snapshot
                )
                comparison = (
                    compare_development_candidate_workspace_snapshot_to_handle(
                        snapshot,
                        workspace,
                    )
                )
                verification = verify_executable_fixture(
                    fixture.bundle,
                    workspace,
                )
                validate_fixture_verification_evidence_binding(
                    verification,
                    fixture.bundle,
                )
                if verification.passed is not True:
                    raise DevelopmentReviewedBashCanaryError(
                        "fixed reviewed Bash program failed its fixture verifier"
                    )
                for value, label in (
                    (source, "reviewed Bash native source"),
                    (compiler, "reviewed Bash compiler"),
                    (built_supervisor, "rebuilt reviewed Bash supervisor"),
                    (pinned_bwrap, "reviewed Bash bwrap"),
                    (pinned_systemd_run, "reviewed Bash systemd-run"),
                    (pinned_systemctl, "reviewed Bash systemctl"),
                ):
                    _verify_pinned_file(value, what=label)
                if not export_evidence:
                    return None
                return _construct_evidence(
                    fixture=fixture,
                    runtime=runtime,
                    request=request,
                    result=result,
                    snapshot=snapshot,
                    comparison=comparison,
                    verification=verification,
                    source=source,
                    compiler=compiler,
                    supervisor=built_supervisor,
                    bwrap=pinned_bwrap,
                    systemd_run=pinned_systemd_run,
                    systemctl=pinned_systemctl,
                    build_contract=build_contract,
                    launch_contract=launch_contract,
                    unit_name=unit_name,
                )
    except DevelopmentReviewedBashCanaryError:
        raise
    except (
        AttributeError,
        DevelopmentCandidateProtocolError,
        DevelopmentCandidateWorkspaceSnapshotError,
        DevelopmentSupervisorCanaryError,
        OSError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as exc:
        raise DevelopmentReviewedBashCanaryError(
            "fixed reviewed Bash canary failed closed"
        ) from exc
    finally:
        for descriptor in reversed(owned_descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        for value in reversed(pinned):
            try:
                os.close(value.descriptor)
            except OSError:
                pass
        if built_supervisor is not None:
            try:
                os.close(built_supervisor.descriptor)
            except OSError:
                pass
        if build_temporary is not None:
            build_temporary.cleanup()


def run_development_reviewed_bash_canary(
    *,
    nonce: bytes | None = None,
) -> DevelopmentReviewedBashCanaryEvidence:
    """Run only the fixed reviewed case with the built-in launch controller."""

    evidence = _run_development_reviewed_bash_canary_impl(
        nonce=nonce,
        runner=_run_fixed_process,
        export_evidence=True,
    )
    if type(evidence) is not DevelopmentReviewedBashCanaryEvidence:
        raise DevelopmentReviewedBashCanaryError(
            "built-in runner did not return exportable evidence"
        )
    return evidence


def _exercise_development_reviewed_bash_canary_with_runner_for_tests(
    *,
    nonce: bytes,
    runner: _ReviewedBashCanaryRunner,
) -> None:
    """Exercise failure gates with an injected runner but mint no evidence."""

    result = _run_development_reviewed_bash_canary_impl(
        nonce=nonce,
        runner=runner,
        export_evidence=False,
    )
    if result is not None:
        raise DevelopmentReviewedBashCanaryError(
            "injected test runner unexpectedly exported evidence"
        )


__all__ = [
    name
    for name in tuple(globals())
    if name.startswith("DEVELOPMENT_REVIEWED_BASH_")
] + [
    "DevelopmentReviewedBashCanaryError",
    "DevelopmentReviewedBashCanaryEvidence",
    "DevelopmentReviewedBashCanaryProcessResult",
    "build_development_reviewed_bash_canary_argv",
    "run_development_reviewed_bash_canary",
    "verify_development_reviewed_bash_canary_evidence",
]
