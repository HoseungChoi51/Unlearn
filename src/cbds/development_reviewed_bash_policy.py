"""Canonical policy for the one fixed reviewed-Bash execution canary.

This policy is controller metadata, not a production sandbox authorization.
It fixes the identities, limits, namespace shape, child argv, and evidence
boundaries that the development canary must use.  The native supervisor only
echoes the policy digest from its request; the trusted controller is
responsible for rebuilding this record and binding it to its exact launch.

The child seccomp profile named here is deliberately a fixed-case denylist.
It is useful evidence that a filter survived into the reviewed program, but it
does not establish a complete syscall allowlist for synthesized Bash.
"""

from __future__ import annotations

from hashlib import sha256
import json
from typing import Final

from .development_candidate_protocol import (
    DEVELOPMENT_CANDIDATE_PROTOCOL_VERSION,
)
from .development_candidate_workspace_snapshot import (
    DEVELOPMENT_CANDIDATE_WORKSPACE_OUTPUT_PROJECTION_SCOPE,
)
from .development_reviewed_bash_fixture import (
    FROZEN_REVIEWED_EXTERNAL_COMMANDS,
    FROZEN_REVIEWED_FIXTURE_DEFINITION_SHA256,
    FROZEN_REVIEWED_INVOCATION_SHA256,
    FROZEN_REVIEWED_PROGRAM_SHA256,
)


DEVELOPMENT_REVIEWED_BASH_POLICY_SCHEMA_VERSION: Final[str] = "1.0.0"
DEVELOPMENT_REVIEWED_BASH_POLICY_RECORD_TYPE: Final[str] = (
    "cbds.development-reviewed-bash-canary-policy"
)
DEVELOPMENT_REVIEWED_BASH_POLICY_SCOPE: Final[str] = (
    "one-fixed-reviewed-program-development-canary-v1"
)

DEVELOPMENT_REVIEWED_BASH_SUPERVISOR_PATH: Final[str] = (
    "/cbds-reviewed-bash-supervisor"
)
DEVELOPMENT_REVIEWED_BASH_PROGRAM_PATH: Final[str] = "/cbds-program.sh"
DEVELOPMENT_REVIEWED_BASH_WORKSPACE_PATH: Final[str] = "/workspace"
DEVELOPMENT_REVIEWED_BASH_UID: Final[int] = 65534
DEVELOPMENT_REVIEWED_BASH_GID: Final[int] = 65534
DEVELOPMENT_REVIEWED_BASH_HOSTNAME: Final[str] = "cbds-reviewed-bash"

DEVELOPMENT_REVIEWED_BASH_WALL_TIMEOUT_USEC: Final[int] = 1_000_000
DEVELOPMENT_REVIEWED_BASH_CPU_TIME_LIMIT_USEC: Final[int] = 500_000
DEVELOPMENT_REVIEWED_BASH_STDOUT_CAP_BYTES: Final[int] = 4_096
DEVELOPMENT_REVIEWED_BASH_STDERR_CAP_BYTES: Final[int] = 4_096
DEVELOPMENT_REVIEWED_BASH_WORKSPACE_SNAPSHOT_CAP_BYTES: Final[int] = 262_144
DEVELOPMENT_REVIEWED_BASH_TMPFS_BYTES: Final[int] = 1_048_576
DEVELOPMENT_REVIEWED_BASH_MEMORY_MAX_BYTES: Final[int] = 134_217_728
DEVELOPMENT_REVIEWED_BASH_TASKS_MAX: Final[int] = 32
DEVELOPMENT_REVIEWED_BASH_NOFILE_MAX: Final[int] = 1_024
# RLIMIT_FSIZE is per created file, not cumulative.  Bubblewrap must first
# materialize the frozen 11,352,352-byte coreutils payload, so its transient
# unit receives the next power-of-two envelope.  The native PID1 then lowers
# only the reviewed Bash child to the intended 1 MiB ceiling before exec.
DEVELOPMENT_REVIEWED_BASH_LAUNCHER_FSIZE_MAX_BYTES: Final[int] = 16_777_216
DEVELOPMENT_REVIEWED_BASH_CHILD_FSIZE_MAX_BYTES: Final[int] = 1_048_576

DEVELOPMENT_REVIEWED_BASH_CHILD_ARGV: Final[tuple[str, ...]] = (
    "/usr/bin/bash",
    "--noprofile",
    "--norc",
    "/proc/self/fd/3",
)
DEVELOPMENT_REVIEWED_BASH_CHILD_ENVIRONMENT: Final[tuple[tuple[str, str], ...]] = (
    ("HOME", "/nonexistent"),
    ("LANG", "C"),
    ("LC_ALL", "C"),
    ("PATH", "/usr/bin:/bin"),
    ("SHELL", "/usr/bin/bash"),
    ("TZ", "UTC"),
)

# These names describe the fixed native filter.  They are intentionally
# grouped by effect rather than pretending to be a complete allowlist.
DEVELOPMENT_REVIEWED_BASH_SECCOMP_DENIED_SYSCALL_FAMILIES: Final[
    tuple[str, ...]
] = (
    "kernel-module-and-reboot",
    "kernel-keyring",
    "mount-and-namespace-reconfiguration",
    "network-socket-creation-and-control",
    "process-introspection-and-kernel-observation",
)


class DevelopmentReviewedBashPolicyError(ValueError):
    """Raised when the fixed canary policy record is malformed or drifts."""


def _canonical_json_bytes(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise DevelopmentReviewedBashPolicyError(
            "reviewed Bash policy is not canonical JSON"
        ) from exc
    return encoded


def development_reviewed_bash_policy_record() -> dict[str, object]:
    """Return the complete immutable controller policy projection."""

    return {
        "schema_version": DEVELOPMENT_REVIEWED_BASH_POLICY_SCHEMA_VERSION,
        "record_type": DEVELOPMENT_REVIEWED_BASH_POLICY_RECORD_TYPE,
        "scope": DEVELOPMENT_REVIEWED_BASH_POLICY_SCOPE,
        "candidate_protocol_version": DEVELOPMENT_CANDIDATE_PROTOCOL_VERSION,
        "reviewed_case": {
            "invocation_sha256": FROZEN_REVIEWED_INVOCATION_SHA256,
            "program_sha256": FROZEN_REVIEWED_PROGRAM_SHA256,
            "fixture_definition_sha256": (
                FROZEN_REVIEWED_FIXTURE_DEFINITION_SHA256
            ),
            "external_commands": list(FROZEN_REVIEWED_EXTERNAL_COMMANDS),
        },
        "namespace": {
            "uid": DEVELOPMENT_REVIEWED_BASH_UID,
            "gid": DEVELOPMENT_REVIEWED_BASH_GID,
            "hostname": DEVELOPMENT_REVIEWED_BASH_HOSTNAME,
            "unshare_all": True,
            "network_namespace_empty": True,
            "further_user_namespaces_disabled": True,
            "new_session": True,
            "supervisor_is_pid1": True,
            "capabilities_dropped": "all",
            "root_remounted_read_only_nonrecursive": True,
            "workspace_descriptor_bind_read_write": True,
            "private_proc": True,
            "private_dev": True,
            "private_tmpfs": True,
        },
        "paths": {
            "supervisor": DEVELOPMENT_REVIEWED_BASH_SUPERVISOR_PATH,
            "program": DEVELOPMENT_REVIEWED_BASH_PROGRAM_PATH,
            "workspace": DEVELOPMENT_REVIEWED_BASH_WORKSPACE_PATH,
        },
        "workspace_snapshot": {
            "wire_magic": "CBDSWSN1",
            "wire_version": 1,
            "scope": DEVELOPMENT_CANDIDATE_WORKSPACE_OUTPUT_PROJECTION_SCOPE,
            "input_projection_serialized": False,
            "input_baseline_revalidated_after_cgroup_quiescence": True,
            "output_projection_compared_to_pinned_workspace": True,
        },
        "child": {
            "argv": list(DEVELOPMENT_REVIEWED_BASH_CHILD_ARGV),
            "environment": {
                name: value
                for name, value in DEVELOPMENT_REVIEWED_BASH_CHILD_ENVIRONMENT
            },
            "working_directory": DEVELOPMENT_REVIEWED_BASH_WORKSPACE_PATH,
            "no_new_privs_before_exec": True,
            "dumpable_disabled_before_exec_only": True,
            "core_limit_bytes": 0,
            "fsize_limit_bytes": (
                DEVELOPMENT_REVIEWED_BASH_CHILD_FSIZE_MAX_BYTES
            ),
            "fsize_limit_installed_by_native_before_exec": True,
            "fixed_case_seccomp_filter_installed": True,
            "seccomp_denied_syscall_families": list(
                DEVELOPMENT_REVIEWED_BASH_SECCOMP_DENIED_SYSCALL_FAMILIES
            ),
            "general_bash_seccomp_policy_verified": False,
        },
        "limits": {
            "wall_timeout_usec": DEVELOPMENT_REVIEWED_BASH_WALL_TIMEOUT_USEC,
            "cpu_time_limit_usec": DEVELOPMENT_REVIEWED_BASH_CPU_TIME_LIMIT_USEC,
            "stdout_cap_bytes": DEVELOPMENT_REVIEWED_BASH_STDOUT_CAP_BYTES,
            "stderr_cap_bytes": DEVELOPMENT_REVIEWED_BASH_STDERR_CAP_BYTES,
            "workspace_snapshot_cap_bytes": (
                DEVELOPMENT_REVIEWED_BASH_WORKSPACE_SNAPSHOT_CAP_BYTES
            ),
            "tmpfs_bytes": DEVELOPMENT_REVIEWED_BASH_TMPFS_BYTES,
            "memory_max_bytes": DEVELOPMENT_REVIEWED_BASH_MEMORY_MAX_BYTES,
            "tasks_max": DEVELOPMENT_REVIEWED_BASH_TASKS_MAX,
            "nofile_max": DEVELOPMENT_REVIEWED_BASH_NOFILE_MAX,
            "launcher_fsize_max_bytes": (
                DEVELOPMENT_REVIEWED_BASH_LAUNCHER_FSIZE_MAX_BYTES
            ),
            "child_fsize_max_bytes": (
                DEVELOPMENT_REVIEWED_BASH_CHILD_FSIZE_MAX_BYTES
            ),
            "launcher_fsize_scope": (
                "bubblewrap-runtime-projection-and-native-supervisor"
            ),
            "memory_swap_max_bytes": 0,
            "core_max_bytes": 0,
            "cpu_quota_percent": 100,
            "systemd_runtime_max_seconds": 5,
            "systemd_timeout_stop_seconds": 1,
        },
        "evidence_boundaries": {
            "runtime_data_and_dlopen_closure_verified": False,
            "externally_trusted_launchers": False,
            "externally_trusted_runtime": False,
            "general_exact_tool_policy_enforced": False,
            "production_cumulative_cpu_enforcement_verified": False,
            "arbitrary_candidate_input_supported": False,
            "candidate_execution_authorized": False,
            "scored_evaluation_eligible": False,
            "model_selection_eligible": False,
            "claim_pipeline_eligible": False,
            "claim_authorized": False,
        },
    }


def canonical_development_reviewed_bash_policy_bytes() -> bytes:
    """Return the canonical bytes whose plain SHA-256 enters the request."""

    record = development_reviewed_bash_policy_record()
    validate_development_reviewed_bash_policy_record(record)
    return _canonical_json_bytes(record)


def development_reviewed_bash_policy_sha256() -> str:
    """Return the exact wire-request identity for the policy record."""

    return sha256(canonical_development_reviewed_bash_policy_bytes()).hexdigest()


def _validate_passive_exact_json(
    observed: object,
    expected: object,
    *,
    path: str,
) -> None:
    """Compare one expected JSON tree without invoking active subclass hooks."""

    if type(observed) is not type(expected):
        raise DevelopmentReviewedBashPolicyError(
            f"reviewed Bash policy field {path} has an active or inexact type"
        )
    if type(expected) is dict:
        observed_dict = observed
        expected_dict = expected
        if any(type(key) is not str for key in observed_dict):
            raise DevelopmentReviewedBashPolicyError(
                f"reviewed Bash policy field {path} has an active key type"
            )
        if len(observed_dict) != len(expected_dict):
            raise DevelopmentReviewedBashPolicyError(
                f"reviewed Bash policy field {path} differs from the fixed mapping"
            )
        for key, expected_value in expected_dict.items():
            if key not in observed_dict:
                raise DevelopmentReviewedBashPolicyError(
                    f"reviewed Bash policy field {path} omits {key!r}"
                )
            _validate_passive_exact_json(
                observed_dict[key],
                expected_value,
                path=f"{path}.{key}",
            )
        return
    if type(expected) is list:
        observed_list = observed
        expected_list = expected
        if len(observed_list) != len(expected_list):
            raise DevelopmentReviewedBashPolicyError(
                f"reviewed Bash policy field {path} differs from the fixed sequence"
            )
        for index, (observed_value, expected_value) in enumerate(
            zip(observed_list, expected_list, strict=True)
        ):
            _validate_passive_exact_json(
                observed_value,
                expected_value,
                path=f"{path}[{index}]",
            )
        return
    if type(expected) not in {str, int, bool, type(None)}:
        raise DevelopmentReviewedBashPolicyError(
            f"fixed reviewed Bash policy field {path} is not passive JSON"
        )
    if observed != expected:
        raise DevelopmentReviewedBashPolicyError(
            f"reviewed Bash policy field {path} differs from the fixed value"
        )


def validate_development_reviewed_bash_policy_record(
    record: dict[str, object],
) -> None:
    """Require one recursively passive exact tree equal to the fixed policy."""

    if type(record) is not dict:
        raise DevelopmentReviewedBashPolicyError(
            "reviewed Bash policy record must be an exact dictionary"
        )
    expected = development_reviewed_bash_policy_record()
    _validate_passive_exact_json(record, expected, path="$")
    if _canonical_json_bytes(record) != _canonical_json_bytes(expected):
        raise DevelopmentReviewedBashPolicyError(
            "reviewed Bash policy canonical bytes differ"
        )


__all__ = [
    name
    for name in tuple(globals())
    if name.startswith("DEVELOPMENT_REVIEWED_BASH_")
] + [
    "DevelopmentReviewedBashPolicyError",
    "canonical_development_reviewed_bash_policy_bytes",
    "development_reviewed_bash_policy_record",
    "development_reviewed_bash_policy_sha256",
    "validate_development_reviewed_bash_policy_record",
]
