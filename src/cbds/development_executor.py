"""Non-scored public-development execution plans that remain fail-closed.

The builders in this module describe the intended Bubblewrap plus user-systemd
boundary without launching it.  Candidate execution is deliberately blocked
until a trusted PID-1 supervisor and a child-only seccomp filter are present,
content-addressed, and covered by integration tests.  Nothing here changes or
relaxes the Docker/Podman scored evaluation contracts.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
from typing import Final, NoReturn

from .development_invocation import (
    DEVELOPMENT_INVOCATION_PROTOCOL,
    DevelopmentInvocation,
    verify_development_invocation,
)
from .development_preflight import (
    DEVELOPMENT_BACKEND,
    DEVELOPMENT_SCOPE,
    canonical_json_bytes,
    verify_development_preflight_sha256,
)


DEVELOPMENT_EXECUTION_SCHEMA_VERSION: Final[str] = "2.0.0"
DEVELOPMENT_EXECUTION_VERSION: Final[str] = "2.0.0"
DEVELOPMENT_SUPERVISOR_PROTOCOL: Final[str] = DEVELOPMENT_INVOCATION_PROTOCOL
DEVELOPMENT_SUPERVISOR_BUNDLE: Final[str] = "/opt/cbds-development"
DEVELOPMENT_SUPERVISOR: Final[str] = (
    "/opt/cbds-development/cbds-development-supervisor"
)
DEVELOPMENT_UNIT: Final[str] = "cbds-public-method-development-v1.service"
_REQUIRED_BLOCKERS: Final[tuple[str, ...]] = (
    "blocked_trusted_pid1_supervisor_missing",
    "blocked_child_seccomp_filter_missing",
    "blocked_cgroup_cpu_time_watcher_missing",
    "blocked_bounded_candidate_capture_missing",
    "blocked_quiescence_enforcer_missing",
    "blocked_exact_tool_policy_missing",
    "blocked_host_usr_unpinned",
)


class DevelopmentExecutionError(ValueError):
    """Raised for malformed development requests or plans."""


class DevelopmentExecutionBlocked(RuntimeError):
    """Raised whenever a caller attempts candidate execution."""

    def __init__(self, blockers: tuple[str, ...]) -> None:
        self.blockers = blockers
        super().__init__(
            "public development candidate execution is blocked: "
            + ", ".join(blockers)
        )


@dataclass(frozen=True, slots=True)
class DevelopmentExecutionPolicy:
    """Immutable limits for a future public-development candidate service."""

    fixture_timeout_seconds: float = 10.0
    kill_grace_seconds: float = 1.0
    cpu_time_seconds: float = 10.0
    memory_bytes: int = 512 * 1024 * 1024
    workspace_bytes: int = 64 * 1024 * 1024
    pids: int = 64
    open_files: int = 64
    stdout_bytes: int = 1024 * 1024
    stderr_bytes: int = 1024 * 1024
    cpu_quota_percent: int = 100
    maximum_program_bytes: int = 64 * 1024
    uid: int = 65534
    gid: int = 65534

    def __post_init__(self) -> None:
        for name in (
            "fixture_timeout_seconds",
            "kill_grace_seconds",
            "cpu_time_seconds",
        ):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or value <= 0
                or value > 3600
            ):
                raise ValueError(f"{name} must be a finite number in (0, 3600]")
        if self.kill_grace_seconds > self.fixture_timeout_seconds:
            raise ValueError("kill_grace_seconds cannot exceed fixture timeout")
        integer_minima = {
            "memory_bytes": 6 * 1024 * 1024,
            "workspace_bytes": 1024 * 1024,
            "pids": 2,
            "open_files": 3,
            "stdout_bytes": 1,
            "stderr_bytes": 1,
            "cpu_quota_percent": 1,
            "maximum_program_bytes": 1,
            "uid": 1,
            "gid": 1,
        }
        for name, minimum in integer_minima.items():
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
                raise ValueError(f"{name} must be an integer >= {minimum}")
        if self.cpu_quota_percent > 1000:
            raise ValueError("cpu_quota_percent must be <= 1000")
        if self.uid > 2**31 - 1 or self.gid > 2**31 - 1:
            raise ValueError("uid and gid must fit the supported non-root range")

    def to_record(self) -> dict[str, int | float]:
        return {
            "fixture_timeout_seconds": float(self.fixture_timeout_seconds),
            "kill_grace_seconds": float(self.kill_grace_seconds),
            "cpu_time_seconds": float(self.cpu_time_seconds),
            "memory_bytes": self.memory_bytes,
            "workspace_bytes": self.workspace_bytes,
            "pids": self.pids,
            "open_files": self.open_files,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "cpu_quota_percent": self.cpu_quota_percent,
            "maximum_program_bytes": self.maximum_program_bytes,
            "uid": self.uid,
            "gid": self.gid,
        }


def build_development_launch_argv(
    policy: DevelopmentExecutionPolicy | None = None,
    *,
    systemd_run: str = "/usr/bin/systemd-run",
    bwrap: str = "/usr/bin/bwrap",
    supervisor_bundle: str = DEVELOPMENT_SUPERVISOR_BUNDLE,
    supervisor: str = DEVELOPMENT_SUPERVISOR,
) -> tuple[str, ...]:
    """Build a fixed future launch argv without candidate bytes.

    The returned command is a review artifact only.  This module has no path
    that executes it while the mandatory supervisor and seccomp blockers are
    present.
    """

    selected = policy if policy is not None else DevelopmentExecutionPolicy()
    if not isinstance(selected, DevelopmentExecutionPolicy):
        raise TypeError("policy must be DevelopmentExecutionPolicy")
    for name, value in (
        ("systemd_run", systemd_run),
        ("bwrap", bwrap),
        ("supervisor_bundle", supervisor_bundle),
        ("supervisor", supervisor),
    ):
        _validate_absolute_path(name, value)
    bundle = Path(supervisor_bundle)
    executable = Path(supervisor)
    try:
        executable.relative_to(bundle)
    except ValueError as exc:
        raise DevelopmentExecutionError(
            "supervisor must be strictly below supervisor_bundle"
        ) from exc
    if executable == bundle:
        raise DevelopmentExecutionError(
            "supervisor must be strictly below supervisor_bundle"
        )

    runtime_max = _seconds_text(
        float(selected.fixture_timeout_seconds)
        + float(selected.kill_grace_seconds)
    )
    properties = (
        f"MemoryMax={selected.memory_bytes}",
        "MemorySwapMax=0",
        f"TasksMax={selected.pids}",
        f"CPUQuota={selected.cpu_quota_percent}%",
        f"LimitNOFILE={selected.open_files}",
        "LimitCORE=0",
        f"RuntimeMaxSec={runtime_max}",
        f"TimeoutStopSec={_seconds_text(float(selected.kill_grace_seconds))}",
        "KillMode=control-group",
        "SendSIGKILL=yes",
        "OOMPolicy=kill",
        "NoNewPrivileges=yes",
        # Bubblewrap uses route netlink during namespace setup; AF_INET and
        # AF_INET6 remain excluded for the eventual supervisor and child.
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
        f"--unit={DEVELOPMENT_UNIT}",
    ]
    for item in properties:
        argv.extend(("--property", item))
    argv.extend(
        (
            bwrap,
            "--unshare-all",
            "--unshare-user",
            "--uid",
            str(selected.uid),
            "--gid",
            str(selected.gid),
            "--disable-userns",
            "--assert-userns-disabled",
            "--die-with-parent",
            "--new-session",
            "--as-pid-1",
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
            "--dir",
            "/opt",
            "--dir",
            supervisor_bundle,
            "--ro-bind",
            supervisor_bundle,
            supervisor_bundle,
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
            supervisor,
            "--protocol",
            DEVELOPMENT_SUPERVISOR_PROTOCOL,
        )
    )
    return tuple(argv)


def prepare_public_development_execution(
    invocation: DevelopmentInvocation,
    preflight_report: Mapping[str, object],
    *,
    policy: DevelopmentExecutionPolicy | None = None,
) -> dict[str, object]:
    """Return a content-safe, permanently blocked candidate launch plan."""

    if type(invocation) is not DevelopmentInvocation:
        raise TypeError("invocation must be an exact DevelopmentInvocation")
    if not verify_development_invocation(invocation):
        raise DevelopmentExecutionError("development invocation is invalid")
    selected = policy if policy is not None else DevelopmentExecutionPolicy()
    if not isinstance(selected, DevelopmentExecutionPolicy):
        raise TypeError("policy must be DevelopmentExecutionPolicy")
    payload = invocation.program
    if not payload or len(payload) > selected.maximum_program_bytes:
        raise DevelopmentExecutionError(
            "program must be nonempty and within maximum_program_bytes"
        )
    executable_paths = _validate_preflight(preflight_report)
    preflight_digest = str(preflight_report["report_sha256"])
    decision = preflight_report.get("decision")
    if not isinstance(decision, Mapping):  # defensive after validation
        raise DevelopmentExecutionError("preflight decision disappeared")
    preflight_blockers = decision.get("blockers")
    if not isinstance(preflight_blockers, list):  # defensive after validation
        raise DevelopmentExecutionError("preflight blockers disappeared")
    blockers = tuple(
        dict.fromkeys(
            [
                *_REQUIRED_BLOCKERS,
                *(str(item) for item in preflight_blockers),
                "blocked_candidate_execution_not_implemented",
            ]
        )
    )
    argv = build_development_launch_argv(
        selected,
        systemd_run=executable_paths["systemd-run"],
        bwrap=executable_paths["bwrap"],
    )
    record: dict[str, object] = {
        "schema_version": DEVELOPMENT_EXECUTION_SCHEMA_VERSION,
        "execution_version": DEVELOPMENT_EXECUTION_VERSION,
        "scope": DEVELOPMENT_SCOPE,
        "backend": DEVELOPMENT_BACKEND,
        "request": invocation.to_audit_record(),
        "invocation_sha256": invocation.invocation_sha256,
        "scored_evaluation_eligible": False,
        "claim_pipeline_eligible": False,
        "tool_policy_enforced": False,
        "candidate_execution_authorized": False,
        "candidate_executed": False,
        "trusted_pid1_supervisor_implemented": False,
        "child_seccomp_filter_implemented": False,
        "program_transport": "framed_stdin_to_trusted_supervisor",
        "program_bytes": len(payload),
        "program_sha256": sha256(payload).hexdigest(),
        "program_plaintext_retained": False,
        "preflight_report_sha256": preflight_digest,
        "limits": selected.to_record(),
        "launch": {
            "argv": list(argv),
            "argv_sha256": sha256(canonical_json_bytes(list(argv))).hexdigest(),
            "shell": False,
            "host_read_write_binds": [],
            "host_read_only_binds": ["/usr", DEVELOPMENT_SUPERVISOR_BUNDLE],
            "workspace": "size_capped_tmpfs",
            "network": "unshared",
            "outer_watchdog_required": True,
            "outer_watchdog_clock": "monotonic",
            "overflow_detection": "cap_plus_one_per_stream",
            "quiescence_required_before_verification": True,
        },
        "decision": {
            "status": "candidate_execution_blocked",
            "blockers": list(blockers),
        },
    }
    record["record_sha256"] = compute_development_execution_sha256(record)
    return record


def execute_public_development_candidate(
    plan: Mapping[str, object], invocation: DevelopmentInvocation
) -> NoReturn:
    """Fail closed; no candidate subprocess path exists in this implementation."""

    validated = _validate_plan(plan)
    if type(invocation) is not DevelopmentInvocation:
        raise TypeError("invocation must be an exact DevelopmentInvocation")
    if not verify_development_invocation(invocation):
        raise DevelopmentExecutionError("development invocation is invalid")
    payload = invocation.program
    if (
        invocation.invocation_sha256 != validated.get("invocation_sha256")
        or len(payload) != validated["program_bytes"]
        or sha256(payload).hexdigest() != validated["program_sha256"]
    ):
        raise DevelopmentExecutionError("invocation does not match the blocked plan")
    decision = validated["decision"]
    if not isinstance(decision, Mapping):  # defensive after validation
        raise DevelopmentExecutionError("development plan decision disappeared")
    blockers = decision["blockers"]
    if not isinstance(blockers, list):  # defensive after validation
        raise DevelopmentExecutionError("development plan blockers disappeared")
    raise DevelopmentExecutionBlocked(tuple(str(item) for item in blockers))


def compute_development_execution_sha256(record: Mapping[str, object]) -> str:
    """Hash a development plan after removing its self-digest."""

    if not isinstance(record, Mapping):
        raise TypeError("record must be a mapping")
    payload = dict(record)
    payload.pop("record_sha256", None)
    return sha256(canonical_json_bytes(payload)).hexdigest()


def verify_development_execution_sha256(record: Mapping[str, object]) -> bool:
    """Return whether a development plan carries its canonical self-digest."""

    if not isinstance(record, Mapping):
        return False
    digest = record.get("record_sha256")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        return False
    try:
        return digest == compute_development_execution_sha256(record)
    except (DevelopmentExecutionError, TypeError, ValueError):
        return False


def _validate_preflight(report: Mapping[str, object]) -> dict[str, str]:
    if not isinstance(report, Mapping) or not verify_development_preflight_sha256(report):
        raise DevelopmentExecutionError("preflight report identity is invalid")
    exact = {
        "scope": DEVELOPMENT_SCOPE,
        "backend": DEVELOPMENT_BACKEND,
        "public_fixtures_only": True,
        "split_role": "method_development",
        "sealed": False,
        "scored_evaluation_eligible": False,
        "claim_pipeline_eligible": False,
        "tool_policy_enforced": False,
        "candidate_execution_authorized": False,
    }
    for name, expected in exact.items():
        if report.get(name) != expected:
            raise DevelopmentExecutionError(
                f"preflight field {name!r} does not match development boundary"
            )
    decision = report.get("decision")
    if not isinstance(decision, Mapping):
        raise DevelopmentExecutionError("preflight decision is missing")
    if decision.get("status") != "candidate_execution_blocked":
        raise DevelopmentExecutionError("preflight must keep candidate execution blocked")
    blockers = decision.get("blockers")
    if (
        not isinstance(blockers, list)
        or not blockers
        or any(not isinstance(item, str) or not item for item in blockers)
    ):
        raise DevelopmentExecutionError("preflight blockers are invalid")
    if not set(_REQUIRED_BLOCKERS).issubset(blockers):
        raise DevelopmentExecutionError("preflight omits mandatory candidate blockers")
    if report.get("all_executables_stable") is not True:
        raise DevelopmentExecutionError("preflight executable identities are not stable")
    executable_records = report.get("executables")
    if not isinstance(executable_records, Mapping):
        raise DevelopmentExecutionError("preflight executable identities are missing")
    resolved: dict[str, str] = {}
    for name in ("bwrap", "systemd-run", "systemctl", "bash"):
        record = executable_records.get(name)
        if not isinstance(record, Mapping) or record.get("status") != "verified":
            raise DevelopmentExecutionError(f"preflight executable {name!r} is unverified")
        path = record.get("resolved_path")
        digest = record.get("sha256")
        byte_count = record.get("bytes")
        if not isinstance(path, str):
            raise DevelopmentExecutionError(f"preflight executable {name!r} path is invalid")
        _validate_absolute_path(name, path)
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise DevelopmentExecutionError(
                f"preflight executable {name!r} digest is invalid"
            )
        if type(byte_count) is not int or byte_count <= 0:
            raise DevelopmentExecutionError(
                f"preflight executable {name!r} byte count is invalid"
            )
        if record.get("stable_after_preflight") is not True:
            raise DevelopmentExecutionError(
                f"preflight executable {name!r} is not stable"
            )
        resolved[name] = path
    return resolved


def _validate_plan(plan: Mapping[str, object]) -> Mapping[str, object]:
    if not isinstance(plan, Mapping) or not verify_development_execution_sha256(plan):
        raise DevelopmentExecutionError("development plan identity is invalid")
    exact = {
        "scope": DEVELOPMENT_SCOPE,
        "backend": DEVELOPMENT_BACKEND,
        "scored_evaluation_eligible": False,
        "claim_pipeline_eligible": False,
        "tool_policy_enforced": False,
        "candidate_execution_authorized": False,
        "candidate_executed": False,
        "trusted_pid1_supervisor_implemented": False,
        "child_seccomp_filter_implemented": False,
    }
    for name, expected in exact.items():
        if plan.get(name) != expected:
            raise DevelopmentExecutionError(f"development plan field {name!r} is invalid")
    if type(plan.get("program_bytes")) is not int or plan["program_bytes"] <= 0:
        raise DevelopmentExecutionError("development plan program_bytes is invalid")
    if re.fullmatch(r"[0-9a-f]{64}", str(plan.get("program_sha256"))) is None:
        raise DevelopmentExecutionError("development plan program_sha256 is invalid")
    invocation_sha256 = plan.get("invocation_sha256")
    if (
        type(invocation_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", invocation_sha256) is None
    ):
        raise DevelopmentExecutionError(
            "development plan invocation_sha256 is invalid"
        )
    request = plan.get("request")
    if not isinstance(request, Mapping):
        raise DevelopmentExecutionError("development plan request is missing")
    request_exact = {
        "invocation_sha256": invocation_sha256,
        "program_bytes": plan["program_bytes"],
        "program_sha256": plan["program_sha256"],
        "candidate_execution_authorized": False,
        "candidate_executed": False,
        "scored_evaluation_eligible": False,
        "model_selection_eligible": False,
        "claim_pipeline_eligible": False,
    }
    for name, expected in request_exact.items():
        if request.get(name) != expected:
            raise DevelopmentExecutionError(
                f"development plan request field {name!r} is invalid"
            )
    decision = plan.get("decision")
    if not isinstance(decision, Mapping) or decision.get("status") != "candidate_execution_blocked":
        raise DevelopmentExecutionError("development plan must remain blocked")
    blockers = decision.get("blockers")
    if not isinstance(blockers, list) or not set(_REQUIRED_BLOCKERS).issubset(blockers):
        raise DevelopmentExecutionError("development plan omits mandatory blockers")
    return plan


def _validate_absolute_path(name: str, value: str) -> None:
    if (
        not isinstance(value, str)
        or not os.path.isabs(value)
        or value.startswith("//")
        or any(character in value for character in ("\x00", "\r", "\n"))
        or ".." in Path(value).parts
        or str(Path(value)) != value
    ):
        raise DevelopmentExecutionError(f"{name} must be a normalized absolute path")


def _seconds_text(value: float) -> str:
    return f"{value:.6f}".rstrip("0").rstrip(".") + "s"


__all__ = [
    "DEVELOPMENT_EXECUTION_SCHEMA_VERSION",
    "DEVELOPMENT_EXECUTION_VERSION",
    "DEVELOPMENT_SUPERVISOR",
    "DEVELOPMENT_SUPERVISOR_BUNDLE",
    "DEVELOPMENT_SUPERVISOR_PROTOCOL",
    "DEVELOPMENT_UNIT",
    "DevelopmentExecutionBlocked",
    "DevelopmentExecutionError",
    "DevelopmentExecutionPolicy",
    "build_development_launch_argv",
    "compute_development_execution_sha256",
    "execute_public_development_candidate",
    "prepare_public_development_execution",
    "verify_development_execution_sha256",
]
