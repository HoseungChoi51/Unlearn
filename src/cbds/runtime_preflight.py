"""Read-only preflight for a pinned local Docker or Podman runtime.

The preflight deliberately stops before execution.  It resolves and hashes the
runtime client, asks only for version/info/local-image metadata, and records
engine-native rootless and cgroup evidence.  A successful decision means only
that the host is eligible for a separately reviewed benign canary; it never
authorizes model-generated or otherwise untrusted code.

All subprocesses use an argv allowlist, ``shell=False``, a scrubbed
environment, a wall-clock timeout, and bounded stdout/stderr capture.  Tests
can inject the executable, cgroup, and command probes and therefore need no
installed container engine.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import selectors
import shutil
import signal
import stat
import subprocess
from time import monotonic
from typing import Any, Final, Literal, cast


PREFLIGHT_SCHEMA_VERSION: Final[str] = "1.0.0"
PREFLIGHT_VERSION: Final[str] = "1.0.0"
RuntimeName = Literal["docker", "podman"]

_SAFE_PATH: Final[str] = (
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)
_IMAGE_REFERENCE_RE: Final[re.Pattern[str]] = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r"@sha256:[0-9a-f]{64}$"
)
_VERSION_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}$"
)
_CONTROLLER_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_LOCAL_DOCKER_HOST_RE: Final[re.Pattern[str]] = re.compile(
    r"^unix:///[A-Za-z0-9_./-]+$"
)
_LOCAL_RUNTIME_DIR_RE: Final[re.Pattern[str]] = re.compile(r"^/run/user/[0-9]+$")
_REQUIRED_CONTROLLERS: Final[tuple[str, ...]] = ("cpu", "memory", "pids")
_PROBE_NAMES: Final[tuple[str, ...]] = ("version", "info", "image_inspect")


class RuntimePreflightError(ValueError):
    """Raised for invalid caller input, not for an unavailable runtime."""


class _ExecutableProbeError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class PreflightLimits:
    """Resource ceilings for the read-only probes."""

    timeout_seconds: float = 5.0
    max_output_bytes: int = 1024 * 1024
    max_executable_bytes: int = 512 * 1024 * 1024
    max_cgroup_bytes: int = 16 * 1024
    max_repo_digests: int = 4096

    def __post_init__(self) -> None:
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not 0 < float(self.timeout_seconds) <= 60
        ):
            raise ValueError("timeout_seconds must be a number in (0, 60]")
        for name in (
            "max_output_bytes",
            "max_executable_bytes",
            "max_cgroup_bytes",
            "max_repo_digests",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")

    def to_record(self) -> dict[str, int | float]:
        return {
            "timeout_seconds": float(self.timeout_seconds),
            "max_output_bytes_per_stream": self.max_output_bytes,
            "max_executable_bytes": self.max_executable_bytes,
            "max_cgroup_bytes": self.max_cgroup_bytes,
            "max_repo_digests": self.max_repo_digests,
        }


@dataclass(frozen=True, slots=True)
class CommandProbeResult:
    """Bounded result returned by an injected or real command runner."""

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


@dataclass(frozen=True, slots=True)
class ExecutableIdentity:
    """Content identity of the resolved runtime client executable."""

    resolved_path: str
    sha256: str
    bytes: int


@dataclass(frozen=True, slots=True)
class HostCgroupEvidence:
    """Bounded evidence read from the host cgroup-v2 controller file."""

    status: str
    version: str | None
    controllers: tuple[str, ...]
    evidence_sha256: str | None


CommandRunner = Callable[..., CommandProbeResult]
ExecutableProbe = Callable[[RuntimeName, str, int], ExecutableIdentity]
CgroupProbe = Callable[[int], HostCgroupEvidence]


def canonical_json_bytes(value: object) -> bytes:
    """Return the canonical JSON representation used for report identity."""

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise RuntimePreflightError("value is not canonical JSON") from error


def compute_preflight_report_sha256(report: Mapping[str, object]) -> str:
    """Hash a report after excluding its self-referential digest field."""

    if not isinstance(report, Mapping):
        raise TypeError("report must be a mapping")
    payload = dict(report)
    payload.pop("report_sha256", None)
    return sha256(canonical_json_bytes(payload)).hexdigest()


def verify_preflight_report_sha256(report: Mapping[str, object]) -> bool:
    """Return whether ``report_sha256`` binds the canonical report content."""

    digest = report.get("report_sha256") if isinstance(report, Mapping) else None
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        return False
    try:
        return digest == compute_preflight_report_sha256(report)
    except (RuntimePreflightError, TypeError):
        return False


def build_preflight_argv(
    runtime: str,
    executable: str,
    image: str,
) -> dict[str, tuple[str, ...]]:
    """Build the complete subprocess argv allowlist for a preflight.

    There is intentionally no generic command builder.  The returned mapping
    contains exactly one version query, one information query, and one local
    image inspection.  It cannot express ``run``, ``pull``, ``build``, or any
    other state-changing engine command.
    """

    selected = _validate_runtime(runtime)
    _validate_image(image)
    if not isinstance(executable, str) or not os.path.isabs(executable):
        raise RuntimePreflightError("executable must be an absolute path")
    if "\x00" in executable or "\n" in executable or "\r" in executable:
        raise RuntimePreflightError("executable path contains forbidden characters")

    if selected == "docker":
        structured = "{{json .}}"
        prefix = (executable,)
    else:
        structured = "json"
        # Podman permits containers.conf to select a remote service. Force the
        # documented boolean global option off so every probe is local.
        prefix = (executable, "--remote=false")
    return {
        "version": (*prefix, "version", "--format", structured),
        "info": (*prefix, "info", "--format", structured),
        # Both engines document the unformatted local inspection result as a
        # JSON array. Avoid relying on Docker-specific template functions.
        "image_inspect": (*prefix, "image", "inspect", image),
    }


def inspect_container_runtime(
    runtime: str,
    image: str,
    *,
    limits: PreflightLimits | None = None,
    runner: CommandRunner | None = None,
    executable_probe: ExecutableProbe | None = None,
    cgroup_probe: CgroupProbe | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Inspect a local runtime without starting or pulling a container.

    Runtime absence and failed probes are represented in the content-addressed
    report instead of being raised.  Only malformed caller inputs raise
    :class:`RuntimePreflightError`.
    """

    selected = _validate_runtime(runtime)
    _validate_image(image)
    selected_limits = limits if limits is not None else PreflightLimits()
    if not isinstance(selected_limits, PreflightLimits):
        raise TypeError("limits must be PreflightLimits")
    selected_runner = runner if runner is not None else _run_bounded
    selected_executable_probe = (
        executable_probe if executable_probe is not None else _probe_executable
    )
    selected_cgroup_probe = cgroup_probe if cgroup_probe is not None else _probe_cgroup
    source_environment = os.environ if environ is None else environ
    clean_environment = _clean_environment(selected, source_environment)

    report: dict[str, object] = {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "preflight_version": PREFLIGHT_VERSION,
        "scope": "read_only_metadata_preflight",
        "runtime": selected,
        "requested_image": image,
        "requested_image_sha256": image.rsplit("@sha256:", 1)[1],
        "limits": selected_limits.to_record(),
        "required_cgroup_controllers": list(_REQUIRED_CONTROLLERS),
        "untrusted_execution_authorized": False,
    }

    try:
        executable = selected_executable_probe(
            selected, _SAFE_PATH, selected_limits.max_executable_bytes
        )
        _validate_executable_identity(executable, selected_limits)
    except _ExecutableProbeError as error:
        status = (
            "blocked_runtime_missing"
            if error.code == "runtime_missing"
            else "blocked_executable_unverified"
        )
        report["executable"] = {"status": error.code}
        report["probes"] = {}
        report["engine"] = _empty_engine_record()
        report["host_cgroup"] = _host_cgroup_record(
            _call_cgroup_probe(selected_cgroup_probe, selected_limits.max_cgroup_bytes)
        )
        report["image"] = _empty_image_record()
        report["decision"] = {"status": status, "blockers": [status]}
        return _finish_report(report)
    except (OSError, TypeError, ValueError):
        status = "blocked_executable_unverified"
        report["executable"] = {"status": "probe_error"}
        report["probes"] = {}
        report["engine"] = _empty_engine_record()
        report["host_cgroup"] = _host_cgroup_record(
            _call_cgroup_probe(selected_cgroup_probe, selected_limits.max_cgroup_bytes)
        )
        report["image"] = _empty_image_record()
        report["decision"] = {"status": status, "blockers": [status]}
        return _finish_report(report)

    report["executable"] = {
        "status": "verified",
        "resolved_path": executable.resolved_path,
        "bytes": executable.bytes,
        "sha256": executable.sha256,
    }
    argv_by_probe = build_preflight_argv(selected, executable.resolved_path, image)
    results: dict[str, CommandProbeResult] = {}
    observations: dict[str, object] = {}
    for name in _PROBE_NAMES:
        argv = argv_by_probe[name]
        result = _call_runner(
            selected_runner,
            argv,
            clean_environment,
            selected_limits,
        )
        results[name] = result
        observations[name] = _command_observation(result, selected_limits)
    report["probes"] = observations

    try:
        executable_after = selected_executable_probe(
            selected, _SAFE_PATH, selected_limits.max_executable_bytes
        )
        _validate_executable_identity(executable_after, selected_limits)
        executable_stable = executable_after == executable
    except (OSError, TypeError, ValueError, _ExecutableProbeError):
        executable_stable = False
    cast(dict[str, object], report["executable"])[
        "stable_after_probes"
    ] = executable_stable

    version_payload, version_state = _load_probe_json(
        results["version"], selected_limits
    )
    info_payload, info_state = _load_probe_json(results["info"], selected_limits)
    image_payload, image_state = _load_probe_json(
        results["image_inspect"], selected_limits
    )

    client_version, server_version, version_fields_valid = _extract_versions(
        selected, version_payload
    )
    service_reachable = (
        info_state == "ok" and isinstance(info_payload, dict)
    )
    rootless_status, rootless_source = _extract_rootless(selected, info_payload)
    engine_cgroup = _extract_engine_cgroup(selected, info_payload)
    engine_record = {
        "version_probe_status": version_state,
        "version_fields_valid": version_fields_valid,
        "client_version": client_version,
        "server_version": server_version,
        "service_reachable": service_reachable,
        "rootless_status": rootless_status,
        "rootless_evidence_source": rootless_source,
        "cgroup": engine_cgroup,
    }
    report["engine"] = engine_record

    host_evidence = _call_cgroup_probe(
        selected_cgroup_probe, selected_limits.max_cgroup_bytes
    )
    host_record = _host_cgroup_record(host_evidence)
    report["host_cgroup"] = host_record

    image_record = _extract_image_record(
        image, image_payload, image_state, selected_limits.max_repo_digests
    )
    report["image"] = image_record

    blockers = _decision_blockers(
        executable_stable=executable_stable,
        version_state=version_state,
        version_fields_valid=version_fields_valid,
        info_state=info_state,
        service_reachable=service_reachable,
        rootless_status=rootless_status,
        engine_cgroup=engine_cgroup,
        host_cgroup=host_record,
        image_state=image_state,
        image_record=image_record,
    )
    decision_status = blockers[0] if blockers else "eligible_for_benign_canary"
    report["decision"] = {"status": decision_status, "blockers": blockers}
    return _finish_report(report)


def _validate_runtime(runtime: str) -> RuntimeName:
    if runtime not in ("docker", "podman"):
        raise RuntimePreflightError("runtime must be 'docker' or 'podman'")
    return cast(RuntimeName, runtime)


def _validate_image(image: str) -> None:
    if (
        not isinstance(image, str)
        or len(image) > 512
        or _IMAGE_REFERENCE_RE.fullmatch(image) is None
    ):
        raise RuntimePreflightError(
            "image must be an exact lowercase repository@sha256 reference"
        )
    repository = image.rsplit("@sha256:", 1)[0]
    # In this restricted grammar a colon after the final slash is a tag, not a
    # registry port. Tags are deliberately forbidden even when a digest is
    # also supplied; a registry port must occur in a component before `/`.
    if repository.rfind(":") > repository.rfind("/"):
        raise RuntimePreflightError(
            "image must not include a tag; registry ports require a repository path"
        )


def _validate_executable_identity(
    identity: ExecutableIdentity, limits: PreflightLimits
) -> None:
    if not isinstance(identity, ExecutableIdentity):
        raise TypeError("executable probe returned the wrong type")
    if not os.path.isabs(identity.resolved_path):
        raise ValueError("resolved executable path is not absolute")
    if re.fullmatch(r"[0-9a-f]{64}", identity.sha256) is None:
        raise ValueError("invalid executable digest")
    if (
        isinstance(identity.bytes, bool)
        or not isinstance(identity.bytes, int)
        or identity.bytes <= 0
        or identity.bytes > limits.max_executable_bytes
    ):
        raise ValueError("invalid executable size")


def _probe_executable(
    runtime: RuntimeName, search_path: str, maximum_bytes: int
) -> ExecutableIdentity:
    candidate = shutil.which(runtime, path=search_path)
    if candidate is None:
        raise _ExecutableProbeError("runtime_missing")
    try:
        path = Path(candidate).resolve(strict=True)
        before = path.stat()
    except OSError as error:
        raise _ExecutableProbeError("executable_unreadable") from error
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise _ExecutableProbeError("executable_not_regular")
    if before.st_size > maximum_bytes:
        raise _ExecutableProbeError("executable_too_large")

    digest = sha256()
    remaining = before.st_size
    try:
        with path.open("rb", buffering=0) as handle:
            opened = os.fstat(handle.fileno())
            if not _same_file_snapshot(before, opened):
                raise _ExecutableProbeError("executable_changed")
            while remaining:
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise _ExecutableProbeError("executable_short_read")
                digest.update(chunk)
                remaining -= len(chunk)
            if handle.read(1):
                raise _ExecutableProbeError("executable_grew")
            after = os.fstat(handle.fileno())
    except _ExecutableProbeError:
        raise
    except OSError as error:
        raise _ExecutableProbeError("executable_unreadable") from error
    if not _same_file_snapshot(before, after):
        raise _ExecutableProbeError("executable_changed")
    return ExecutableIdentity(str(path), digest.hexdigest(), before.st_size)


def _same_file_snapshot(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_dev,
        first.st_ino,
        first.st_mode,
        first.st_size,
        first.st_mtime_ns,
        first.st_ctime_ns,
    ) == (
        second.st_dev,
        second.st_ino,
        second.st_mode,
        second.st_size,
        second.st_mtime_ns,
        second.st_ctime_ns,
    )


def _clean_environment(
    runtime: RuntimeName, source: Mapping[str, str]
) -> dict[str, str]:
    environment = {
        "PATH": _SAFE_PATH,
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
    }
    try:
        home = pwd.getpwuid(os.getuid()).pw_dir
    except (KeyError, OSError):
        home = "/nonexistent"
    if isinstance(home, str) and os.path.isabs(home) and "\x00" not in home:
        environment["HOME"] = home
    else:
        environment["HOME"] = "/nonexistent"

    if runtime == "docker":
        # Do not load Docker contexts from HOME.  An explicitly configured
        # local Unix socket is retained only after a strict syntax check.
        environment["DOCKER_CONFIG"] = "/nonexistent"
        docker_host = source.get("DOCKER_HOST")
        if (
            isinstance(docker_host, str)
            and _LOCAL_DOCKER_HOST_RE.fullmatch(docker_host) is not None
            and ".." not in Path(docker_host.removeprefix("unix://")).parts
        ):
            environment["DOCKER_HOST"] = docker_host
    else:
        runtime_dir = source.get("XDG_RUNTIME_DIR")
        if (
            isinstance(runtime_dir, str)
            and _LOCAL_RUNTIME_DIR_RE.fullmatch(runtime_dir) is not None
            and runtime_dir == f"/run/user/{os.getuid()}"
        ):
            environment["XDG_RUNTIME_DIR"] = runtime_dir
    return environment


def _call_runner(
    runner: CommandRunner,
    argv: tuple[str, ...],
    environment: Mapping[str, str],
    limits: PreflightLimits,
) -> CommandProbeResult:
    try:
        result = runner(
            argv,
            env=dict(environment),
            timeout_seconds=float(limits.timeout_seconds),
            max_output_bytes=limits.max_output_bytes,
        )
    except (OSError, subprocess.SubprocessError, TypeError, ValueError):
        return CommandProbeResult(returncode=None, launch_error=True)
    if not isinstance(result, CommandProbeResult):
        return CommandProbeResult(returncode=None, launch_error=True)
    return result


def _run_bounded(
    argv: tuple[str, ...],
    *,
    env: Mapping[str, str],
    timeout_seconds: float,
    max_output_bytes: int,
) -> CommandProbeResult:
    """Run one allowlisted probe while retaining at most the output ceilings."""

    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=dict(env),
            close_fds=True,
            start_new_session=True,
        )
    except OSError:
        return CommandProbeResult(returncode=None, launch_error=True)

    assert process.stdout is not None
    assert process.stderr is not None
    streams = {process.stdout.fileno(): ("stdout", process.stdout)}
    streams[process.stderr.fileno()] = ("stderr", process.stderr)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    for descriptor, (_, stream) in streams.items():
        os.set_blocking(descriptor, False)
        selector.register(stream, selectors.EVENT_READ, descriptor)

    deadline = monotonic() + timeout_seconds
    timed_out = False
    output_truncated = False
    killed = False
    try:
        while selector.get_map():
            remaining_time = deadline - monotonic()
            if remaining_time <= 0:
                timed_out = True
                _kill_process_group(process)
                killed = True
                break
            events = selector.select(min(remaining_time, 0.1))
            if not events and process.poll() is not None:
                # Pipes may still contain buffered data, so continue selecting.
                continue
            for key, _ in events:
                descriptor = cast(int, key.data)
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
                    output_truncated = True
                    _kill_process_group(process)
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
        # Reaching this branch is defensive; normal EOF means the process has
        # closed both pipes and should already be exiting.
        try:
            process.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process_group(process)
            killed = True
    try:
        returncode = process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)
        try:
            returncode = process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            returncode = None
    return CommandProbeResult(
        returncode=returncode,
        stdout=bytes(buffers["stdout"]),
        stderr=bytes(buffers["stderr"]),
        timed_out=timed_out,
        output_truncated=output_truncated,
    )


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill()
        except OSError:
            pass


def _command_observation(
    result: CommandProbeResult, limits: PreflightLimits
) -> dict[str, object]:
    oversized = (
        len(result.stdout) > limits.max_output_bytes
        or len(result.stderr) > limits.max_output_bytes
    )
    if result.launch_error:
        status = "launch_error"
    elif result.timed_out:
        status = "timeout"
    elif result.output_truncated or oversized:
        status = "output_limit_exceeded"
    elif result.returncode != 0:
        status = "nonzero_exit"
    else:
        status = "completed"
    return {
        "status": status,
        "returncode": result.returncode,
        "stdout_bytes": min(len(result.stdout), limits.max_output_bytes),
        "stdout_sha256": sha256(
            result.stdout[: limits.max_output_bytes]
        ).hexdigest(),
        "stderr_bytes": min(len(result.stderr), limits.max_output_bytes),
        "stderr_sha256": sha256(
            result.stderr[: limits.max_output_bytes]
        ).hexdigest(),
        "raw_output_retained": False,
    }


def _load_probe_json(
    result: CommandProbeResult, limits: PreflightLimits
) -> tuple[object | None, str]:
    if result.launch_error:
        return None, "launch_error"
    if result.timed_out:
        return None, "timeout"
    if (
        result.output_truncated
        or len(result.stdout) > limits.max_output_bytes
        or len(result.stderr) > limits.max_output_bytes
    ):
        return None, "output_limit_exceeded"
    if result.returncode != 0:
        return None, "nonzero_exit"
    try:
        text = result.stdout.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        return None, "malformed_output"
    return value, "ok"


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r}")


def _extract_versions(
    runtime: RuntimeName, payload: object | None
) -> tuple[str | None, str | None, bool]:
    if not isinstance(payload, dict):
        return None, None, False
    client: object | None = None
    server: object | None = None
    if runtime == "docker":
        client_object = payload.get("Client")
        server_object = payload.get("Server")
        if isinstance(client_object, dict):
            client = client_object.get("Version")
        if isinstance(server_object, dict):
            server = server_object.get("Version")
    else:
        # Podman has emitted both {Client, Server} and a flat Version field
        # across supported releases.  Accept only these explicit structures.
        client_object = payload.get("Client")
        server_object = payload.get("Server")
        if isinstance(client_object, dict):
            client = client_object.get("Version") or client_object.get("version")
        if isinstance(server_object, dict):
            server = server_object.get("Version") or server_object.get("version")
        flat = payload.get("Version") or payload.get("version")
        if client is None:
            client = flat
        if server is None:
            server = flat
    valid_client = _validated_version(client)
    valid_server = _validated_version(server)
    return (
        valid_client,
        valid_server,
        valid_client is not None and valid_server is not None,
    )


def _validated_version(value: object) -> str | None:
    if isinstance(value, str) and _VERSION_RE.fullmatch(value) is not None:
        return value
    return None


def _extract_rootless(
    runtime: RuntimeName, payload: object | None
) -> tuple[str, str | None]:
    if not isinstance(payload, dict):
        return "unverified", None
    if runtime == "docker":
        declared = payload.get("Rootless")
        options = payload.get("SecurityOptions")
        option_rootless = False
        if isinstance(options, list):
            for option in options:
                if not isinstance(option, str):
                    return "malformed", None
                fields = {field.strip() for field in option.split(",")}
                if "name=rootless" in fields or "rootless" in fields:
                    option_rootless = True
        elif options is not None:
            return "malformed", None
        if declared is False and option_rootless:
            return "malformed", None
        if declared is True:
            return "verified_rootless", "info.Rootless"
        if declared is False:
            return "verified_rootful", "info.Rootless"
        if declared is not None:
            return "malformed", None
        if option_rootless:
            return "verified_rootless", "info.SecurityOptions"
        return "unverified", None

    host = payload.get("host")
    security = host.get("security") if isinstance(host, dict) else None
    if isinstance(security, dict) and security.get("rootless") is True:
        return "verified_rootless", "info.host.security.rootless"
    if isinstance(security, dict) and security.get("rootless") is False:
        return "verified_rootful", "info.host.security.rootless"
    return "unverified", None


def _extract_engine_cgroup(
    runtime: RuntimeName, payload: object | None
) -> dict[str, object]:
    if not isinstance(payload, dict):
        return {"version": None, "manager": None, "evidence_valid": False}
    if runtime == "docker":
        version = payload.get("CgroupVersion")
        manager = payload.get("CgroupDriver")
    else:
        host = payload.get("host")
        if not isinstance(host, dict):
            return {"version": None, "manager": None, "evidence_valid": False}
        version = host.get("cgroupVersion")
        manager = host.get("cgroupManager")
    normalized_version = _normalize_cgroup_version(version)
    normalized_manager = (
        manager
        if isinstance(manager, str)
        and re.fullmatch(r"[A-Za-z0-9_.+-]{1,64}", manager) is not None
        else None
    )
    return {
        "version": normalized_version,
        "manager": normalized_manager,
        "evidence_valid": (
            normalized_version is not None and normalized_manager is not None
        ),
    }


def _normalize_cgroup_version(value: object) -> str | None:
    if value in (2, "2", "v2", "V2"):
        return "v2"
    if value in (1, "1", "v1", "V1"):
        return "v1"
    return None


def _read_stable_bounded(path: Path, maximum_bytes: int) -> tuple[str, bytes | None]:
    try:
        before = path.stat()
    except OSError:
        return "unavailable", None
    if not stat.S_ISREG(before.st_mode):
        return "not_regular", None
    if before.st_size > maximum_bytes:
        return "output_limit_exceeded", None
    try:
        with path.open("rb", buffering=0) as handle:
            payload = handle.read(maximum_bytes + 1)
            after = os.fstat(handle.fileno())
    except OSError:
        return "unreadable", None
    if len(payload) > maximum_bytes:
        return "output_limit_exceeded", None
    if not _same_file_snapshot(before, after):
        return "changed_during_read", None
    return "verified", payload


def _probe_cgroup(
    maximum_bytes: int,
    *,
    membership_path: Path = Path("/proc/self/cgroup"),
    cgroup_root: Path = Path("/sys/fs/cgroup"),
) -> HostCgroupEvidence:
    membership_status, membership_payload = _read_stable_bounded(
        membership_path, maximum_bytes
    )
    if membership_status != "verified" or membership_payload is None:
        return HostCgroupEvidence(
            f"membership_{membership_status}", None, (), None
        )
    try:
        membership_text = membership_payload.decode("ascii")
    except UnicodeDecodeError:
        return HostCgroupEvidence("membership_malformed", None, (), None)
    unified = [
        line.split(":", 2)[2]
        for line in membership_text.splitlines()
        if line.startswith("0::") and len(line.split(":", 2)) == 3
    ]
    if len(unified) != 1:
        return HostCgroupEvidence("membership_malformed", None, (), None)
    location = unified[0]
    pure_location = PurePosixPath(location)
    if (
        not pure_location.is_absolute()
        or location.startswith("//")
        or str(pure_location) != location
        or any(part in {".", ".."} for part in pure_location.parts)
    ):
        return HostCgroupEvidence("membership_malformed", None, (), None)

    candidate = cgroup_root.joinpath(*pure_location.parts[1:], "cgroup.controllers")
    try:
        resolved_root = cgroup_root.resolve(strict=True)
        resolved_candidate = candidate.resolve(strict=True)
    except OSError:
        return HostCgroupEvidence("controllers_unavailable", None, (), None)
    if resolved_root not in resolved_candidate.parents:
        return HostCgroupEvidence("membership_malformed", None, (), None)
    controller_status, controller_payload = _read_stable_bounded(
        resolved_candidate, maximum_bytes
    )
    if controller_status != "verified" or controller_payload is None:
        return HostCgroupEvidence(
            f"controllers_{controller_status}", None, (), None
        )
    try:
        values = controller_payload.decode("ascii").split()
    except UnicodeDecodeError:
        return HostCgroupEvidence("controllers_malformed", None, (), None)
    if any(_CONTROLLER_RE.fullmatch(value) is None for value in values):
        return HostCgroupEvidence("controllers_malformed", None, (), None)
    controllers = tuple(sorted(set(values)))
    evidence_digest = sha256(
        canonical_json_bytes(
            {
                "domain": "cbds.runtime_preflight.cgroup_v2_membership.v1",
                "membership_sha256": sha256(membership_payload).hexdigest(),
                "controllers_sha256": sha256(controller_payload).hexdigest(),
            }
        )
    ).hexdigest()
    return HostCgroupEvidence("verified", "v2", controllers, evidence_digest)


def _call_cgroup_probe(probe: CgroupProbe, maximum_bytes: int) -> HostCgroupEvidence:
    try:
        evidence = probe(maximum_bytes)
    except (OSError, TypeError, ValueError):
        return HostCgroupEvidence("probe_error", None, (), None)
    if not isinstance(evidence, HostCgroupEvidence):
        return HostCgroupEvidence("probe_error", None, (), None)
    if (
        not isinstance(evidence.status, str)
        or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", evidence.status) is None
        or evidence.version not in (None, "v1", "v2")
        or not isinstance(evidence.controllers, tuple)
        or any(
            not isinstance(item, str) or _CONTROLLER_RE.fullmatch(item) is None
            for item in evidence.controllers
        )
        or evidence.evidence_sha256 is not None
        and re.fullmatch(r"[0-9a-f]{64}", evidence.evidence_sha256) is None
    ):
        return HostCgroupEvidence("malformed", None, (), None)
    return HostCgroupEvidence(
        evidence.status,
        evidence.version,
        tuple(sorted(set(evidence.controllers))),
        evidence.evidence_sha256,
    )


def _host_cgroup_record(evidence: HostCgroupEvidence) -> dict[str, object]:
    controllers = tuple(sorted(set(evidence.controllers)))
    missing = [item for item in _REQUIRED_CONTROLLERS if item not in controllers]
    return {
        "status": evidence.status,
        "version": evidence.version,
        "controllers": list(controllers),
        "controllers_sha256": sha256(canonical_json_bytes(list(controllers))).hexdigest(),
        "evidence_sha256": evidence.evidence_sha256,
        "missing_required_controllers": missing,
    }


def _extract_image_record(
    requested: str,
    payload: object | None,
    state: str,
    maximum_digests: int,
) -> dict[str, object]:
    empty = _empty_image_record()
    empty["inspect_status"] = state
    if state != "ok":
        return empty
    if (
        not isinstance(payload, list)
        or len(payload) != 1
        or not isinstance(payload[0], dict)
    ):
        empty["inspect_status"] = "malformed_output"
        return empty
    digests = payload[0].get("RepoDigests")
    if not isinstance(digests, list) or len(digests) > maximum_digests:
        empty["inspect_status"] = "malformed_output"
        return empty
    values: list[str] = []
    for item in digests:
        if not isinstance(item, str) or _IMAGE_REFERENCE_RE.fullmatch(item) is None:
            empty["inspect_status"] = "malformed_output"
            return empty
        values.append(item)
    unique = sorted(set(values))
    return {
        "inspect_status": "ok",
        "local_repo_digest_count": len(unique),
        "local_repo_digests_sha256": sha256(canonical_json_bytes(unique)).hexdigest(),
        "exact_repo_digest_match": requested in unique,
        "raw_repo_digests_retained": False,
    }


def _empty_engine_record() -> dict[str, object]:
    return {
        "version_probe_status": "not_run",
        "version_fields_valid": False,
        "client_version": None,
        "server_version": None,
        "service_reachable": False,
        "rootless_status": "unverified",
        "rootless_evidence_source": None,
        "cgroup": {"version": None, "manager": None, "evidence_valid": False},
    }


def _empty_image_record() -> dict[str, object]:
    return {
        "inspect_status": "not_run",
        "local_repo_digest_count": 0,
        "local_repo_digests_sha256": sha256(canonical_json_bytes([])).hexdigest(),
        "exact_repo_digest_match": False,
        "raw_repo_digests_retained": False,
    }


def _decision_blockers(
    *,
    executable_stable: bool,
    version_state: str,
    version_fields_valid: bool,
    info_state: str,
    service_reachable: bool,
    rootless_status: str,
    engine_cgroup: Mapping[str, object],
    host_cgroup: Mapping[str, object],
    image_state: str,
    image_record: Mapping[str, object],
) -> list[str]:
    blockers: list[str] = []
    if not executable_stable:
        blockers.append("blocked_executable_changed")
    if version_state == "timeout" or info_state == "timeout" or image_state == "timeout":
        blockers.append("blocked_probe_timeout")
    if (
        version_state == "output_limit_exceeded"
        or info_state == "output_limit_exceeded"
        or image_state == "output_limit_exceeded"
    ):
        blockers.append("blocked_probe_output_limit")
    if version_state != "ok" or not version_fields_valid:
        blockers.append("blocked_version_probe")
    if info_state != "ok" or not service_reachable:
        blockers.append("blocked_service_unreachable")
    if rootless_status == "verified_rootful":
        blockers.append("blocked_rootful_runtime")
    elif rootless_status != "verified_rootless":
        blockers.append("blocked_rootless_unverified")
    if (
        engine_cgroup.get("version") != "v2"
        or engine_cgroup.get("manager") != "systemd"
        or engine_cgroup.get("evidence_valid") is not True
    ):
        blockers.append("blocked_engine_cgroup_unverified")
    if host_cgroup.get("status") != "verified" or host_cgroup.get("version") != "v2":
        blockers.append("blocked_host_cgroup_unverified")
    if host_cgroup.get("missing_required_controllers"):
        blockers.append("blocked_cgroup_controllers")
    if image_state == "nonzero_exit" and service_reachable:
        blockers.append("blocked_image_not_local")
    elif image_record.get("inspect_status") != "ok":
        blockers.append("blocked_image_inspect")
    elif image_record.get("exact_repo_digest_match") is not True:
        blockers.append("blocked_image_digest_mismatch")
    # Preserve priority while eliminating duplicates introduced by coupled
    # failures (for example timeout plus an unreachable service).
    return list(dict.fromkeys(blockers))


def _finish_report(report: dict[str, object]) -> dict[str, object]:
    report["report_sha256"] = compute_preflight_report_sha256(report)
    return report


__all__ = [
    "CommandProbeResult",
    "ExecutableIdentity",
    "HostCgroupEvidence",
    "PREFLIGHT_SCHEMA_VERSION",
    "PREFLIGHT_VERSION",
    "PreflightLimits",
    "RuntimePreflightError",
    "build_preflight_argv",
    "compute_preflight_report_sha256",
    "inspect_container_runtime",
    "verify_preflight_report_sha256",
]
