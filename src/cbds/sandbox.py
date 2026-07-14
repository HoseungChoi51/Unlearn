"""Safe construction of rootless Docker or Podman evaluation commands.

This module only constructs argv.  It never starts a container and never
accepts a host path or bind mount.  Programs are supplied to the resulting
command on standard input.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math
from pathlib import PurePosixPath
import re
import shlex

from .response import ProgramLanguage


class ContainerRuntime(str, Enum):
    """Supported rootless container clients."""

    DOCKER = "docker"
    PODMAN = "podman"


_PINNED_IMAGE = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r"(?:[:][A-Za-z0-9_][A-Za-z0-9_.-]*)?"
    r"@sha256:[0-9a-f]{64}$"
)
_SAFE_ENV_VALUE = re.compile(r"^[^\x00\r\n]*$")
_MIN_MEMORY_BYTES = 6 * 1024 * 1024
_DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


@dataclass(frozen=True, slots=True)
class SandboxConfig:
    """Immutable resource and isolation policy for one fresh container.

    The selected Docker daemon or Podman service must itself run rootlessly;
    the argv additionally fixes a non-root container UID/GID.  ``output_bytes``
    is the maximum emitted by each of stdout and stderr.
    """

    image: str
    runtime: ContainerRuntime = ContainerRuntime.DOCKER
    uid: int = 65534
    gid: int = 65534
    workspace: str = "/workspace"
    cpu_count: float = 1.0
    memory_bytes: int = 512 * 1024 * 1024
    pids_limit: int = 64
    tmpfs_bytes: int = 64 * 1024 * 1024
    output_bytes: int = 1024 * 1024
    timeout_seconds: int = 10
    kill_grace_seconds: int = 1
    open_files_limit: int = 64
    umask: int = 0o077
    locale: str = "C.UTF-8"
    timezone: str = "UTC"

    def __post_init__(self) -> None:
        try:
            runtime = ContainerRuntime(self.runtime)
        except (TypeError, ValueError) as exc:
            raise ValueError("runtime must be 'docker' or 'podman'") from exc
        object.__setattr__(self, "runtime", runtime)

        if not isinstance(self.image, str) or _PINNED_IMAGE.fullmatch(self.image) is None:
            raise ValueError(
                "image must be a registry/repository reference pinned by a lowercase "
                "sha256 digest"
            )
        _validate_nonroot_id("uid", self.uid)
        _validate_nonroot_id("gid", self.gid)
        _validate_workspace(self.workspace)

        if isinstance(self.cpu_count, bool) or not isinstance(self.cpu_count, (int, float)):
            raise ValueError("cpu_count must be a finite positive number")
        if not math.isfinite(float(self.cpu_count)) or self.cpu_count <= 0:
            raise ValueError("cpu_count must be a finite positive number")

        _validate_int("memory_bytes", self.memory_bytes, minimum=_MIN_MEMORY_BYTES)
        _validate_int("pids_limit", self.pids_limit, minimum=1)
        _validate_int("tmpfs_bytes", self.tmpfs_bytes, minimum=1024 * 1024)
        _validate_int("output_bytes", self.output_bytes, minimum=1)
        _validate_int("timeout_seconds", self.timeout_seconds, minimum=1)
        _validate_int("kill_grace_seconds", self.kill_grace_seconds, minimum=1)
        _validate_int("open_files_limit", self.open_files_limit, minimum=3)
        if isinstance(self.umask, bool) or not isinstance(self.umask, int):
            raise ValueError("umask must be an integer between 0 and 0o777")
        if not 0 <= self.umask <= 0o777:
            raise ValueError("umask must be an integer between 0 and 0o777")
        _validate_env_value("locale", self.locale)
        _validate_env_value("timezone", self.timezone)


def _validate_nonroot_id(name: str, value: int) -> None:
    _validate_int(name, value, minimum=1)
    if value > 2**31 - 1:
        raise ValueError(f"{name} is outside the supported range")


def _validate_int(name: str, value: int, *, minimum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")


def _validate_workspace(workspace: str) -> None:
    if not isinstance(workspace, str) or not workspace:
        raise ValueError("workspace must be an absolute container path")
    if any(character in workspace for character in ("\x00", "\r", "\n", ":", ",")):
        raise ValueError("workspace contains a character unsafe for a tmpfs specification")
    path = PurePosixPath(workspace)
    if (
        not path.is_absolute()
        or workspace.startswith("//")
        or ".." in path.parts
        or path == PurePosixPath("/")
    ):
        raise ValueError("workspace must be a non-root absolute container path")
    if str(path) != workspace:
        raise ValueError("workspace must be a normalized absolute container path")


def _validate_env_value(name: str, value: str) -> None:
    if not isinstance(value, str) or not value or _SAFE_ENV_VALUE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a non-empty single-line string")


def build_sandbox_argv(
    config: SandboxConfig,
    language: ProgramLanguage = ProgramLanguage.BASH,
) -> tuple[str, ...]:
    """Build hardened container argv for a program supplied on stdin.

    The returned tuple can be passed directly to :mod:`subprocess`.  It has no
    bind mounts, volumes, host paths, shell interpolation, container socket, or
    network.  The caller remains responsible for an outer wall-clock watchdog
    and for verifying that the selected runtime service is rootless.
    """

    if not isinstance(config, SandboxConfig):
        raise TypeError("config must be a SandboxConfig")
    try:
        selected_language = ProgramLanguage(language)
    except (TypeError, ValueError) as exc:
        raise ValueError("language must be 'bash' or 'python'") from exc

    workspace = config.workspace
    tmpdir = f"{workspace}/tmp"
    environment = (
        ("LANG", config.locale),
        ("LC_ALL", config.locale),
        ("TZ", config.timezone),
        ("HOME", workspace),
        ("TMPDIR", tmpdir),
        ("PATH", _DEFAULT_PATH),
        ("BASH_ENV", "/dev/null"),
        ("ENV", "/dev/null"),
        ("PYTHONHASHSEED", "0"),
        ("PYTHONDONTWRITEBYTECODE", "1"),
        ("PYTHONNOUSERSITE", "1"),
    )

    tmpfs_options = (
        f"rw,nosuid,nodev,size={config.tmpfs_bytes},mode=0700,"
        f"uid={config.uid},gid={config.gid}"
    )
    cpu_text = format(float(config.cpu_count), ".12g")
    argv: list[str] = [
        config.runtime.value,
        "run",
        "--rm",
        "--interactive",
        "--init",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--ipc=none",
        f"--user={config.uid}:{config.gid}",
        f"--pids-limit={config.pids_limit}",
        f"--cpus={cpu_text}",
        f"--memory={config.memory_bytes}",
        f"--memory-swap={config.memory_bytes}",
        f"--stop-timeout={config.kill_grace_seconds}",
        f"--ulimit=nofile={config.open_files_limit}:{config.open_files_limit}",
        f"--ulimit=nproc={config.pids_limit}:{config.pids_limit}",
        "--ulimit=core=0:0",
        f"--tmpfs={workspace}:{tmpfs_options}",
        f"--workdir={workspace}",
        "--hostname=cbds-sandbox",
    ]
    for name, value in environment:
        argv.append(f"--env={name}={value}")

    argv.extend(
        (
            config.image,
            "/usr/bin/env",
            "-i",
            *(f"{name}={value}" for name, value in environment),
            "/bin/bash",
            "--noprofile",
            "--norc",
            "-c",
            _runner_script(config, selected_language),
        )
    )
    return tuple(argv)


def _runner_script(config: SandboxConfig, language: ProgramLanguage) -> str:
    workspace = shlex.quote(config.workspace)
    tmpdir = shlex.quote(f"{config.workspace}/tmp")
    if language is ProgramLanguage.BASH:
        interpreter = "/bin/bash --noprofile --norc -s"
    else:
        interpreter = "/usr/bin/python3 -I -"

    # Values interpolated below are validated integers or shell-quoted paths;
    # model output is never interpolated and arrives only on stdin.
    return "\n".join(
        (
            "set -o pipefail",
            f"umask {config.umask:03o}",
            f"mkdir -p -- {tmpdir}",
            f"cd -- {workspace}",
            (
                f"/usr/bin/timeout --signal=TERM --kill-after={config.kill_grace_seconds}s "
                f"{config.timeout_seconds}s {interpreter} "
                f"> >(/usr/bin/head -c {config.output_bytes}) "
                f"2> >(/usr/bin/head -c {config.output_bytes} >&2)"
            ),
        )
    )


__all__ = [
    "ContainerRuntime",
    "SandboxConfig",
    "build_sandbox_argv",
]
