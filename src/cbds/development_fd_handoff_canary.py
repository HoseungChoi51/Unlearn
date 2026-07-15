"""Permanently nonauthorizing sealed-memfd subprocess handoff canary.

This module exercises one narrow development primitive: a CLOEXEC duplicate
from a :class:`DevelopmentRuntimeFdSnapshot` must be absent after an ordinary
exec and must survive only when explicitly named in ``subprocess``
``pass_fds``.  A hash-bound fixed helper, executed through an already-open
interpreter FD, then hashes the inherited descriptor and reports its inode
identity and seals.

The probe never receives candidate bytes and never starts a candidate.  It is
not a systemd-scope, Bubblewrap, PID-1, seccomp, cgroup, or scored-launch test.
Those facts are permanent invariants of the typed evidence below rather than
policy supplied by a caller.
"""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
from hashlib import sha256
import json
import os
import selectors
import stat
import subprocess
import sys
import time
from typing import Final

from .development_runtime_bundle import canonical_development_runtime_json_bytes
from .development_runtime_fd_snapshot import DevelopmentRuntimeFdSnapshot
from .development_runtime_materializer import DevelopmentRuntimeMaterializedEntry


DEVELOPMENT_FD_HANDOFF_CANARY_SCHEMA_VERSION: Final[str] = "1.0.0"
DEVELOPMENT_FD_HANDOFF_CANARY_VERSION: Final[str] = "1.0.0"
DEVELOPMENT_FD_HANDOFF_CANARY_KIND: Final[str] = (
    "cbds-development-fd-handoff-canary-evidence"
)
DEVELOPMENT_FD_HANDOFF_CANARY_ALGORITHM: Final[str] = (
    "sealed-memfd-cloexec-negative-explicit-pass-fds-positive-v1"
)
HANDOFF_DESCRIPTOR_FLOOR: Final[int] = 128
HANDOFF_PROBE_TIMEOUT_SECONDS: Final[float] = 10.0
MAXIMUM_CHILD_STDOUT_BYTES: Final[int] = 4096
MAXIMUM_CHILD_STDERR_BYTES: Final[int] = 4096
MAXIMUM_INTERPRETER_BYTES: Final[int] = 128 * 1024 * 1024
_HASH_CHUNK_BYTES: Final[int] = 1024 * 1024

_HELPER_SOURCE: Final[str] = r'''import errno
import fcntl
import hashlib
import json
import os
import sys

fd = int(sys.argv[1])
executable_fd = int(sys.argv[2])
if executable_fd == fd:
    raise RuntimeError("executable and payload descriptors alias")
os.close(executable_fd)
open_fds = []
scan_fd = os.open(
    "/proc/self/fd",
    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
)
try:
    names = os.listdir(scan_fd)
finally:
    os.close(scan_fd)
for name in names:
    if not name.isascii() or not name.isdecimal():
        raise RuntimeError("unexpected /proc/self/fd entry")
    candidate = int(name)
    try:
        os.fstat(candidate)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
    else:
        open_fds.append(candidate)
open_fds.sort()
try:
    metadata = os.fstat(fd)
except OSError as exc:
    if exc.errno != errno.EBADF:
        raise
    record = {"open_fds": open_fds, "state": "closed"}
else:
    digest = hashlib.sha256()
    offset = 0
    while offset < metadata.st_size:
        block = os.pread(fd, min(1048576, metadata.st_size - offset), offset)
        if not block:
            raise RuntimeError("descriptor ended before its declared size")
        digest.update(block)
        offset += len(block)
    if os.pread(fd, 1, metadata.st_size):
        raise RuntimeError("descriptor grew beyond its declared size")
    record = {
        "descriptor_inheritable": os.get_inheritable(fd),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "open_fds": open_fds,
        "seals": fcntl.fcntl(fd, fcntl.F_GET_SEALS),
        "sha256": digest.hexdigest(),
        "size": metadata.st_size,
        "state": "open",
    }
sys.stdout.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
'''
HANDOFF_HELPER_SOURCE_SHA256: Final[str] = sha256(
    _HELPER_SOURCE.encode("utf-8")
).hexdigest()


class DevelopmentFdHandoffCanaryError(RuntimeError):
    """Raised whenever the descriptor-survival canary cannot prove its facts."""


def _lower_sha256(value: object, *, what: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DevelopmentFdHandoffCanaryError(f"{what} must be lowercase SHA-256")
    return value


def _plain_nonnegative_int(value: object, *, what: str) -> int:
    if type(value) is not int or value < 0:
        raise DevelopmentFdHandoffCanaryError(
            f"{what} must be a nonnegative plain integer"
        )
    return value


def _required_seals() -> int:
    names = ("F_GET_SEALS", "F_SEAL_SEAL", "F_SEAL_SHRINK", "F_SEAL_GROW", "F_SEAL_WRITE")
    values: dict[str, int] = {}
    for name in names:
        value = getattr(fcntl, name, None)
        if type(value) is not int or value < 0:
            raise DevelopmentFdHandoffCanaryError(
                f"required Linux memfd primitive {name} is unavailable"
            )
        values[name] = value
    duplicate = getattr(fcntl, "F_DUPFD_CLOEXEC", None)
    if type(duplicate) is not int or duplicate < 0:
        raise DevelopmentFdHandoffCanaryError(
            "required Linux descriptor primitive F_DUPFD_CLOEXEC is unavailable"
        )
    return (
        values["F_SEAL_SEAL"]
        | values["F_SEAL_SHRINK"]
        | values["F_SEAL_GROW"]
        | values["F_SEAL_WRITE"]
    )


@dataclass(frozen=True, slots=True)
class DevelopmentFdHandoffCanaryEvidence:
    """Typed proof of one nonauthorizing Python-subprocess FD survival probe."""

    source_snapshot_sha256: str
    source_manifest_sha256: str
    source_evidence_sha256: str
    destination_path: str
    expected_size: int
    expected_content_sha256: str
    parent_device: int
    parent_inode: int
    parent_seals: int
    parent_content_sha256: str
    child_device: int
    child_inode: int
    child_size: int
    child_seals: int
    child_content_sha256: str
    negative_child_open_fds: tuple[int, ...]
    positive_child_open_fds: tuple[int, ...]
    helper_source_sha256: str
    child_executable_path: str
    child_executable_sha256: str
    evidence_sha256: str
    schema_version: str = DEVELOPMENT_FD_HANDOFF_CANARY_SCHEMA_VERSION
    canary_version: str = DEVELOPMENT_FD_HANDOFF_CANARY_VERSION
    kind: str = DEVELOPMENT_FD_HANDOFF_CANARY_KIND
    algorithm: str = DEVELOPMENT_FD_HANDOFF_CANARY_ALGORITHM
    source_descriptor_cloexec_verified: bool = True
    negative_exec_descriptor_absence_verified: bool = True
    explicit_pass_fds_survival_verified: bool = True
    inherited_descriptor_exact_binding_verified: bool = True
    inherited_descriptor_exclusivity_verified: bool = True
    sealed_payload_handoff_verified: bool = True
    subprocess_fd_handoff_verified: bool = True
    helper_source_binding_verified: bool = True
    child_executable_fd_binding_verified: bool = True
    fixed_probe_child_executed: bool = True
    externally_trusted_child_executable: bool = False
    harmless_probe_child_executed: bool = False
    systemd_scope_handoff_verified: bool = False
    bubblewrap_handoff_verified: bool = False
    namespace_runtime_closure_verified: bool = False
    materialized_mode_handoff_verified: bool = False
    fd_bound_launch_handoff: bool = False
    runtime_launch_performed: bool = False
    launch_eligible: bool = False
    candidate_program_present: bool = False
    candidate_execution_authorized: bool = False
    candidate_executed: bool = False
    scored_evaluation_eligible: bool = False
    claim_pipeline_eligible: bool = False

    def __post_init__(self) -> None:
        exact: dict[str, object] = {
            "schema_version": DEVELOPMENT_FD_HANDOFF_CANARY_SCHEMA_VERSION,
            "canary_version": DEVELOPMENT_FD_HANDOFF_CANARY_VERSION,
            "kind": DEVELOPMENT_FD_HANDOFF_CANARY_KIND,
            "algorithm": DEVELOPMENT_FD_HANDOFF_CANARY_ALGORITHM,
            "helper_source_sha256": HANDOFF_HELPER_SOURCE_SHA256,
            "source_descriptor_cloexec_verified": True,
            "negative_exec_descriptor_absence_verified": True,
            "explicit_pass_fds_survival_verified": True,
            "inherited_descriptor_exact_binding_verified": True,
            "inherited_descriptor_exclusivity_verified": True,
            "sealed_payload_handoff_verified": True,
            "subprocess_fd_handoff_verified": True,
            "helper_source_binding_verified": True,
            "child_executable_fd_binding_verified": True,
            "fixed_probe_child_executed": True,
            "externally_trusted_child_executable": False,
            "harmless_probe_child_executed": False,
            "systemd_scope_handoff_verified": False,
            "bubblewrap_handoff_verified": False,
            "namespace_runtime_closure_verified": False,
            "materialized_mode_handoff_verified": False,
            "fd_bound_launch_handoff": False,
            "runtime_launch_performed": False,
            "launch_eligible": False,
            "candidate_program_present": False,
            "candidate_execution_authorized": False,
            "candidate_executed": False,
            "scored_evaluation_eligible": False,
            "claim_pipeline_eligible": False,
        }
        for field, expected in exact.items():
            actual = getattr(self, field)
            if type(actual) is not type(expected) or actual != expected:
                raise DevelopmentFdHandoffCanaryError(
                    f"canary evidence field {field!r} is invalid"
                )
        for field in (
            "source_snapshot_sha256",
            "source_manifest_sha256",
            "source_evidence_sha256",
            "expected_content_sha256",
            "parent_content_sha256",
            "child_content_sha256",
            "helper_source_sha256",
            "child_executable_sha256",
            "evidence_sha256",
        ):
            _lower_sha256(getattr(self, field), what=field)
        if type(self.destination_path) is not str or not self.destination_path.startswith("/"):
            raise DevelopmentFdHandoffCanaryError(
                "destination_path must be an absolute plain string"
            )
        if (
            type(self.child_executable_path) is not str
            or not self.child_executable_path.startswith("/")
            or os.path.normpath(self.child_executable_path) != self.child_executable_path
        ):
            raise DevelopmentFdHandoffCanaryError(
                "child_executable_path must be normalized absolute text"
            )
        for field in (
            "expected_size",
            "parent_device",
            "parent_inode",
            "parent_seals",
            "child_device",
            "child_inode",
            "child_size",
            "child_seals",
        ):
            _plain_nonnegative_int(getattr(self, field), what=field)
        for field in ("negative_child_open_fds", "positive_child_open_fds"):
            value = getattr(self, field)
            if (
                type(value) is not tuple
                or any(type(item) is not int or item < 0 for item in value)
                or value != tuple(sorted(set(value)))
            ):
                raise DevelopmentFdHandoffCanaryError(
                    f"{field} must be a unique sorted tuple of descriptors"
                )
        if self.negative_child_open_fds != (0, 1, 2):
            raise DevelopmentFdHandoffCanaryError(
                "negative child inherited an unrelated descriptor"
            )
        if (
            len(self.positive_child_open_fds) != 4
            or self.positive_child_open_fds[:3] != (0, 1, 2)
            or self.positive_child_open_fds[3] < HANDOFF_DESCRIPTOR_FLOOR
        ):
            raise DevelopmentFdHandoffCanaryError(
                "positive child descriptor set is not exact"
            )
        if (
            self.parent_device != self.child_device
            or self.parent_inode != self.child_inode
            or self.expected_size != self.child_size
            or self.parent_seals != self.child_seals
            or self.expected_content_sha256 != self.parent_content_sha256
            or self.expected_content_sha256 != self.child_content_sha256
        ):
            raise DevelopmentFdHandoffCanaryError(
                "canary evidence does not bind the inherited descriptor exactly"
            )
        required = _required_seals()
        if self.parent_seals != required:
            raise DevelopmentFdHandoffCanaryError(
                "canary evidence carries an unexpected memfd seal set"
            )
        expected_evidence = _compute_evidence_sha256(self)
        if self.evidence_sha256 != expected_evidence:
            raise DevelopmentFdHandoffCanaryError(
                "canary evidence self-digest is invalid"
            )

    def to_record(self, *, include_self_digest: bool = True) -> dict[str, object]:
        self.__post_init__()
        return _evidence_record_unchecked(self, include_self_digest=include_self_digest)


def _evidence_record_unchecked(
    evidence: DevelopmentFdHandoffCanaryEvidence,
    *,
    include_self_digest: bool,
) -> dict[str, object]:
    record: dict[str, object] = {
        "schema_version": evidence.schema_version,
        "canary_version": evidence.canary_version,
        "kind": evidence.kind,
        "algorithm": evidence.algorithm,
        "source_snapshot_sha256": evidence.source_snapshot_sha256,
        "source_manifest_sha256": evidence.source_manifest_sha256,
        "source_evidence_sha256": evidence.source_evidence_sha256,
        "destination_path": evidence.destination_path,
        "expected_size": evidence.expected_size,
        "expected_content_sha256": evidence.expected_content_sha256,
        "parent_device": evidence.parent_device,
        "parent_inode": evidence.parent_inode,
        "parent_seals": evidence.parent_seals,
        "parent_content_sha256": evidence.parent_content_sha256,
        "child_device": evidence.child_device,
        "child_inode": evidence.child_inode,
        "child_size": evidence.child_size,
        "child_seals": evidence.child_seals,
        "child_content_sha256": evidence.child_content_sha256,
        "negative_child_open_fds": list(evidence.negative_child_open_fds),
        "positive_child_open_fds": list(evidence.positive_child_open_fds),
        "helper_source_sha256": evidence.helper_source_sha256,
        "child_executable_path": evidence.child_executable_path,
        "child_executable_sha256": evidence.child_executable_sha256,
        "source_descriptor_cloexec_verified": evidence.source_descriptor_cloexec_verified,
        "negative_exec_descriptor_absence_verified": evidence.negative_exec_descriptor_absence_verified,
        "explicit_pass_fds_survival_verified": evidence.explicit_pass_fds_survival_verified,
        "inherited_descriptor_exact_binding_verified": evidence.inherited_descriptor_exact_binding_verified,
        "inherited_descriptor_exclusivity_verified": evidence.inherited_descriptor_exclusivity_verified,
        "sealed_payload_handoff_verified": evidence.sealed_payload_handoff_verified,
        "subprocess_fd_handoff_verified": evidence.subprocess_fd_handoff_verified,
        "helper_source_binding_verified": evidence.helper_source_binding_verified,
        "child_executable_fd_binding_verified": evidence.child_executable_fd_binding_verified,
        "fixed_probe_child_executed": evidence.fixed_probe_child_executed,
        "externally_trusted_child_executable": evidence.externally_trusted_child_executable,
        "harmless_probe_child_executed": evidence.harmless_probe_child_executed,
        "systemd_scope_handoff_verified": evidence.systemd_scope_handoff_verified,
        "bubblewrap_handoff_verified": evidence.bubblewrap_handoff_verified,
        "namespace_runtime_closure_verified": evidence.namespace_runtime_closure_verified,
        "materialized_mode_handoff_verified": evidence.materialized_mode_handoff_verified,
        "fd_bound_launch_handoff": evidence.fd_bound_launch_handoff,
        "runtime_launch_performed": evidence.runtime_launch_performed,
        "launch_eligible": evidence.launch_eligible,
        "candidate_program_present": evidence.candidate_program_present,
        "candidate_execution_authorized": evidence.candidate_execution_authorized,
        "candidate_executed": evidence.candidate_executed,
        "scored_evaluation_eligible": evidence.scored_evaluation_eligible,
        "claim_pipeline_eligible": evidence.claim_pipeline_eligible,
    }
    if include_self_digest:
        record["evidence_sha256"] = evidence.evidence_sha256
    return record


def _compute_evidence_sha256(evidence: DevelopmentFdHandoffCanaryEvidence) -> str:
    return sha256(
        canonical_development_runtime_json_bytes(
            _evidence_record_unchecked(evidence, include_self_digest=False)
        )
    ).hexdigest()


def _hash_descriptor(descriptor: int, size: int) -> str:
    digest = sha256()
    offset = 0
    while offset < size:
        block = os.pread(descriptor, min(_HASH_CHUNK_BYTES, size - offset), offset)
        if not block:
            raise DevelopmentFdHandoffCanaryError(
                "sealed descriptor ended before its authenticated size"
            )
        digest.update(block)
        offset += len(block)
    if os.pread(descriptor, 1, size):
        raise DevelopmentFdHandoffCanaryError(
            "sealed descriptor grew beyond its authenticated size"
        )
    return digest.hexdigest()


def _interpreter_metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_interpreter_identity() -> tuple[str, str, tuple[int, ...], int]:
    """Pin and hash the exact interpreter inode later supplied to execve."""

    if type(sys.executable) is not str or not sys.executable:
        raise DevelopmentFdHandoffCanaryError("Python executable path is unavailable")
    try:
        resolved = os.path.realpath(sys.executable, strict=True)
    except (OSError, TypeError, ValueError) as exc:
        raise DevelopmentFdHandoffCanaryError(
            "Python executable path cannot be resolved"
        ) from exc
    if (
        type(resolved) is not str
        or not resolved.startswith("/")
        or os.path.normpath(resolved) != resolved
    ):
        raise DevelopmentFdHandoffCanaryError(
            "Python executable path is not normalized absolute text"
        )
    required_flags = ("O_CLOEXEC", "O_NOFOLLOW")
    if any(type(getattr(os, name, None)) is not int for name in required_flags):
        raise DevelopmentFdHandoffCanaryError(
            "required no-follow executable inspection primitives are unavailable"
        )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            resolved,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 1
            or before.st_size > MAXIMUM_INTERPRETER_BYTES
            or before.st_mode & 0o111 == 0
        ):
            raise DevelopmentFdHandoffCanaryError(
                "Python executable is not a bounded executable regular file"
            )
        digest = _hash_descriptor(descriptor, before.st_size)
        after = os.fstat(descriptor)
        named = os.stat(resolved, follow_symlinks=False)
        identity = _interpreter_metadata_identity(before)
        if (
            identity != _interpreter_metadata_identity(after)
            or identity != _interpreter_metadata_identity(named)
            or os.get_inheritable(descriptor)
        ):
            raise DevelopmentFdHandoffCanaryError(
                "Python executable changed during its named inspection"
            )
        result = descriptor
        descriptor = None
        return resolved, digest, identity, result
    except DevelopmentFdHandoffCanaryError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise DevelopmentFdHandoffCanaryError(
            "Python executable inspection failed closed"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _kill_and_reap(process: subprocess.Popen[bytes]) -> None:
    try:
        process.kill()
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=1.0)
    except (subprocess.TimeoutExpired, ProcessLookupError):
        pass


def _reject_child_json_number(_value: str) -> object:
    raise ValueError("child frame contains a forbidden JSON number")


def _strict_child_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if type(key) is not str or key in value:
            raise ValueError("child frame contains a duplicate or non-text key")
        value[key] = item
    return value


def _bounded_child_probe(
    executable_path: str,
    executable_descriptor: int,
    descriptor: int,
    *,
    pass_descriptor: bool,
    helper_source: str,
) -> dict[str, object]:
    if (
        type(helper_source) is not str
        or type(executable_descriptor) is not int
        or executable_descriptor < 0
        or executable_descriptor == descriptor
    ):
        raise DevelopmentFdHandoffCanaryError(
            "probe helper or executable descriptor is invalid"
        )
    executable_fd_path = f"/proc/self/fd/{executable_descriptor}"
    argv = (
        executable_path,
        "-I",
        "-S",
        "-c",
        helper_source,
        str(descriptor),
        str(executable_descriptor),
    )
    passed = (
        (executable_descriptor, descriptor)
        if pass_descriptor
        else (executable_descriptor,)
    )
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    try:
        process = subprocess.Popen(
            argv,
            executable=executable_fd_path,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=tuple(sorted(passed)),
            env={"LC_ALL": "C", "TZ": "UTC"},
        )
        if process.stdout is None or process.stderr is None:
            raise DevelopmentFdHandoffCanaryError(
                "probe child did not expose bounded output pipes"
            )
        selector = selectors.DefaultSelector()
        streams = {
            process.stdout.fileno(): ("stdout", MAXIMUM_CHILD_STDOUT_BYTES),
            process.stderr.fileno(): ("stderr", MAXIMUM_CHILD_STDERR_BYTES),
        }
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        for file_descriptor in streams:
            os.set_blocking(file_descriptor, False)
            selector.register(file_descriptor, selectors.EVENT_READ)
        deadline = time.monotonic() + HANDOFF_PROBE_TIMEOUT_SECONDS
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DevelopmentFdHandoffCanaryError("probe child timed out")
            ready = selector.select(remaining)
            if not ready:
                raise DevelopmentFdHandoffCanaryError("probe child timed out")
            for key, _events in ready:
                file_descriptor = int(key.fd)
                label, maximum = streams[file_descriptor]
                try:
                    block = os.read(file_descriptor, 4096)
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(file_descriptor)
                    continue
                buffers[label].extend(block)
                if len(buffers[label]) > maximum:
                    raise DevelopmentFdHandoffCanaryError(
                        f"probe child {label} exceeded its byte bound"
                    )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DevelopmentFdHandoffCanaryError("probe child timed out")
        return_code = process.wait(timeout=remaining)
        if return_code != 0 or buffers["stderr"]:
            raise DevelopmentFdHandoffCanaryError(
                "probe child failed or emitted diagnostic output"
            )
        try:
            text = bytes(buffers["stdout"]).decode("utf-8", errors="strict")
            if not text.endswith("\n") or text.count("\n") != 1:
                raise ValueError("child output is not one bounded frame")
            value = json.loads(
                text,
                object_pairs_hook=_strict_child_object,
                parse_float=_reject_child_json_number,
                parse_constant=_reject_child_json_number,
            )
        except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise DevelopmentFdHandoffCanaryError(
                "probe child emitted a malformed bounded frame"
            ) from exc
        if type(value) is not dict or any(type(key) is not str for key in value):
            raise DevelopmentFdHandoffCanaryError(
                "probe child frame must be a plain JSON object"
            )
        return value
    except DevelopmentFdHandoffCanaryError:
        if process is not None:
            _kill_and_reap(process)
        raise
    except (OSError, subprocess.SubprocessError, TypeError, ValueError) as exc:
        if process is not None:
            _kill_and_reap(process)
        raise DevelopmentFdHandoffCanaryError(
            "probe child launch failed closed"
        ) from exc
    finally:
        if selector is not None:
            selector.close()
        if process is not None:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()


def _select_regular_entry(
    snapshot: DevelopmentRuntimeFdSnapshot,
) -> DevelopmentRuntimeMaterializedEntry:
    if type(snapshot.entries) is not tuple:
        raise DevelopmentFdHandoffCanaryError(
            "snapshot entries must be an exact tuple"
        )
    regular = tuple(entry for entry in snapshot.entries if entry.kind == "regular")
    if not regular:
        raise DevelopmentFdHandoffCanaryError(
            "snapshot contains no regular descriptor to probe"
        )
    selected = regular[0]
    if type(selected) is not DevelopmentRuntimeMaterializedEntry:
        raise DevelopmentFdHandoffCanaryError(
            "snapshot regular entry has an unexpected type"
        )
    selected.__post_init__()
    return selected


def _construct_evidence(
    *,
    snapshot: DevelopmentRuntimeFdSnapshot,
    entry: DevelopmentRuntimeMaterializedEntry,
    parent_metadata: os.stat_result,
    seals: int,
    content_sha256: str,
    negative: dict[str, object],
    child: dict[str, object],
    helper_source_sha256: str,
    executable_path: str,
    executable_sha256: str,
) -> DevelopmentFdHandoffCanaryEvidence:
    fields: dict[str, object] = {
        "source_snapshot_sha256": snapshot.snapshot_sha256,
        "source_manifest_sha256": snapshot.source_manifest_sha256,
        "source_evidence_sha256": snapshot.source_evidence_sha256,
        "destination_path": entry.destination_path,
        "expected_size": entry.size,
        "expected_content_sha256": entry.content_sha256,
        "parent_device": parent_metadata.st_dev,
        "parent_inode": parent_metadata.st_ino,
        "parent_seals": seals,
        "parent_content_sha256": content_sha256,
        "child_device": child["device"],
        "child_inode": child["inode"],
        "child_size": child["size"],
        "child_seals": child["seals"],
        "child_content_sha256": child["sha256"],
        "negative_child_open_fds": tuple(negative["open_fds"]),
        "positive_child_open_fds": tuple(child["open_fds"]),
        "helper_source_sha256": helper_source_sha256,
        "child_executable_path": executable_path,
        "child_executable_sha256": executable_sha256,
    }
    record: dict[str, object] = {
        "schema_version": DEVELOPMENT_FD_HANDOFF_CANARY_SCHEMA_VERSION,
        "canary_version": DEVELOPMENT_FD_HANDOFF_CANARY_VERSION,
        "kind": DEVELOPMENT_FD_HANDOFF_CANARY_KIND,
        "algorithm": DEVELOPMENT_FD_HANDOFF_CANARY_ALGORITHM,
        **fields,
        "source_descriptor_cloexec_verified": True,
        "negative_exec_descriptor_absence_verified": True,
        "explicit_pass_fds_survival_verified": True,
        "inherited_descriptor_exact_binding_verified": True,
        "inherited_descriptor_exclusivity_verified": True,
        "sealed_payload_handoff_verified": True,
        "subprocess_fd_handoff_verified": True,
        "helper_source_binding_verified": True,
        "child_executable_fd_binding_verified": True,
        "fixed_probe_child_executed": True,
        "externally_trusted_child_executable": False,
        "harmless_probe_child_executed": False,
        "systemd_scope_handoff_verified": False,
        "bubblewrap_handoff_verified": False,
        "namespace_runtime_closure_verified": False,
        "materialized_mode_handoff_verified": False,
        "fd_bound_launch_handoff": False,
        "runtime_launch_performed": False,
        "launch_eligible": False,
        "candidate_program_present": False,
        "candidate_execution_authorized": False,
        "candidate_executed": False,
        "scored_evaluation_eligible": False,
        "claim_pipeline_eligible": False,
    }
    digest = sha256(canonical_development_runtime_json_bytes(record)).hexdigest()
    return DevelopmentFdHandoffCanaryEvidence(
        evidence_sha256=digest,
        **fields,  # type: ignore[arg-type]
    )


def run_development_fd_handoff_canary(
    snapshot: DevelopmentRuntimeFdSnapshot,
) -> DevelopmentFdHandoffCanaryEvidence:
    """Probe one sealed snapshot descriptor without authorizing any launch.

    The sole argument is an already-authenticated FD snapshot.  The first
    regular destination entry is selected deterministically.  Any unavailable
    Linux primitive, unexpected seal, CLOEXEC failure, child protocol error,
    digest mismatch, or inode mismatch raises rather than returning partial or
    positive-looking evidence.  The caller retains ownership of ``snapshot``;
    this function closes every duplicate it creates and never closes the
    snapshot.  All payload reads are positional, so shared open-file-description
    offsets cannot influence the result.
    """

    if type(snapshot) is not DevelopmentRuntimeFdSnapshot:
        raise DevelopmentFdHandoffCanaryError(
            "snapshot must be exact DevelopmentRuntimeFdSnapshot"
        )
    if type(snapshot.closed) is not bool or snapshot.closed:
        raise DevelopmentFdHandoffCanaryError("snapshot is already closed")
    try:
        snapshot_record = snapshot.to_record()
    except (OSError, TypeError, ValueError) as exc:
        raise DevelopmentFdHandoffCanaryError(
            "snapshot failed its immutable structural replay"
        ) from exc
    if type(snapshot_record) is not dict:
        raise DevelopmentFdHandoffCanaryError(
            "snapshot structural record must be a plain dictionary"
        )
    for field in (
        "fd_bound_launch_handoff",
        "launch_eligible",
        "candidate_execution_authorized",
        "scored_evaluation_eligible",
        "claim_pipeline_eligible",
    ):
        if getattr(snapshot, field, None) is not False:
            raise DevelopmentFdHandoffCanaryError(
                f"source snapshot authority field {field!r} is not false"
            )
    for field in (
        "snapshot_sha256",
        "source_manifest_sha256",
        "source_evidence_sha256",
    ):
        _lower_sha256(getattr(snapshot, field), what=f"snapshot {field}")
    helper_source = _HELPER_SOURCE
    if (
        type(helper_source) is not str
        or sha256(helper_source.encode("utf-8")).hexdigest()
        != HANDOFF_HELPER_SOURCE_SHA256
    ):
        raise DevelopmentFdHandoffCanaryError(
            "probe helper source differs from its frozen digest"
        )
    helper_source_sha256 = HANDOFF_HELPER_SOURCE_SHA256
    required_seals = _required_seals()
    entry = _select_regular_entry(snapshot)
    try:
        rebound_entry = snapshot.regular_entry(entry.destination_path)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise DevelopmentFdHandoffCanaryError(
            "snapshot could not rebind the selected regular entry"
        ) from exc
    if (
        type(rebound_entry) is not DevelopmentRuntimeMaterializedEntry
        or rebound_entry != entry
    ):
        raise DevelopmentFdHandoffCanaryError(
            "snapshot regular-entry lookup differs from its immutable inventory"
        )
    expected_digest = _lower_sha256(
        entry.content_sha256, what="selected entry content_sha256"
    )
    expected_size = _plain_nonnegative_int(entry.size, what="selected entry size")
    executable_path: str | None = None
    executable_sha256: str | None = None
    executable_identity: tuple[int, ...] | None = None
    executable_descriptor: int | None = None
    snapshot_duplicate: int | None = None
    handoff_descriptor: int | None = None
    try:
        (
            executable_path,
            executable_sha256,
            executable_identity,
            executable_descriptor,
        ) = _open_interpreter_identity()
        snapshot_duplicate = snapshot.duplicate_regular_fd(
            entry.destination_path
        )
        if type(snapshot_duplicate) is not int or snapshot_duplicate < 0:
            raise DevelopmentFdHandoffCanaryError(
                "snapshot returned an invalid descriptor duplicate"
            )
        if os.get_inheritable(snapshot_duplicate):
            raise DevelopmentFdHandoffCanaryError(
                "snapshot duplicate is not CLOEXEC"
            )
        duplicate_command = getattr(fcntl, "F_DUPFD_CLOEXEC")
        handoff_descriptor = fcntl.fcntl(
            snapshot_duplicate,
            duplicate_command,
            HANDOFF_DESCRIPTOR_FLOOR,
        )
        if type(handoff_descriptor) is not int or handoff_descriptor < HANDOFF_DESCRIPTOR_FLOOR:
            raise DevelopmentFdHandoffCanaryError(
                "high-number CLOEXEC descriptor duplication failed"
            )
        os.close(snapshot_duplicate)
        snapshot_duplicate = None
        if os.get_inheritable(handoff_descriptor):
            raise DevelopmentFdHandoffCanaryError(
                "high-number handoff descriptor is not CLOEXEC"
            )
        metadata = os.fstat(handoff_descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != expected_size:
            raise DevelopmentFdHandoffCanaryError(
                "handoff descriptor metadata differs from the selected entry"
            )
        seals = fcntl.fcntl(handoff_descriptor, getattr(fcntl, "F_GET_SEALS"))
        if type(seals) is not int or seals != required_seals:
            raise DevelopmentFdHandoffCanaryError(
                "handoff descriptor memfd seals differ from the required seal set"
            )
        parent_digest = _hash_descriptor(handoff_descriptor, expected_size)
        if parent_digest != expected_digest:
            raise DevelopmentFdHandoffCanaryError(
                "handoff descriptor digest differs from the authenticated entry"
            )

        negative = _bounded_child_probe(
            executable_path,
            executable_descriptor,
            handoff_descriptor,
            pass_descriptor=False,
            helper_source=helper_source,
        )
        if negative != {"open_fds": [0, 1, 2], "state": "closed"}:
            raise DevelopmentFdHandoffCanaryError(
                "CLOEXEC negative probe unexpectedly observed the descriptor"
            )
        if os.get_inheritable(handoff_descriptor):
            raise DevelopmentFdHandoffCanaryError(
                "negative child probe changed parent CLOEXEC state"
            )
        positive = _bounded_child_probe(
            executable_path,
            executable_descriptor,
            handoff_descriptor,
            pass_descriptor=True,
            helper_source=helper_source,
        )
        expected_keys = {
            "descriptor_inheritable",
            "device",
            "inode",
            "open_fds",
            "seals",
            "sha256",
            "size",
            "state",
        }
        if set(positive) != expected_keys or positive.get("state") != "open":
            raise DevelopmentFdHandoffCanaryError(
                "explicit pass_fds probe emitted an unexpected record"
            )
        if positive.get("descriptor_inheritable") is not True:
            raise DevelopmentFdHandoffCanaryError(
                "pass_fds did not make the child descriptor exec-survivable"
            )
        for field in ("device", "inode", "seals", "size"):
            _plain_nonnegative_int(positive.get(field), what=f"child {field}")
        open_fds = positive.get("open_fds")
        if (
            type(open_fds) is not list
            or any(type(item) is not int or item < 0 for item in open_fds)
            or open_fds != [0, 1, 2, handoff_descriptor]
        ):
            raise DevelopmentFdHandoffCanaryError(
                "explicit pass_fds child inherited an unrelated descriptor"
            )
        _lower_sha256(positive.get("sha256"), what="child sha256")
        if (
            positive["device"] != metadata.st_dev
            or positive["inode"] != metadata.st_ino
            or positive["size"] != expected_size
            or positive["seals"] != seals
            or positive["sha256"] != expected_digest
        ):
            raise DevelopmentFdHandoffCanaryError(
                "explicit pass_fds child did not observe the exact sealed memfd"
            )
        after = os.fstat(handoff_descriptor)
        if (
            after.st_dev != metadata.st_dev
            or after.st_ino != metadata.st_ino
            or after.st_size != metadata.st_size
            or os.get_inheritable(handoff_descriptor)
            or fcntl.fcntl(handoff_descriptor, getattr(fcntl, "F_GET_SEALS")) != seals
            or _hash_descriptor(handoff_descriptor, expected_size) != expected_digest
        ):
            raise DevelopmentFdHandoffCanaryError(
                "parent descriptor binding changed across child probes"
            )
        executable_after = os.fstat(executable_descriptor)
        named_executable_after = os.stat(
            executable_path,
            follow_symlinks=False,
        )
        if (
            _interpreter_metadata_identity(executable_after)
            != executable_identity
            or _interpreter_metadata_identity(named_executable_after)
            != executable_identity
            or os.get_inheritable(executable_descriptor)
            or _hash_descriptor(
                executable_descriptor,
                executable_after.st_size,
            )
            != executable_sha256
        ):
            raise DevelopmentFdHandoffCanaryError(
                "pinned Python executable changed across child probes"
            )
        if snapshot.closed:
            raise DevelopmentFdHandoffCanaryError(
                "source snapshot closed during the descriptor probe"
            )
        return _construct_evidence(
            snapshot=snapshot,
            entry=entry,
            parent_metadata=metadata,
            seals=seals,
            content_sha256=parent_digest,
            negative=negative,
            child=positive,
            helper_source_sha256=helper_source_sha256,
            executable_path=executable_path,
            executable_sha256=executable_sha256,
        )
    except DevelopmentFdHandoffCanaryError:
        raise
    except (OSError, TypeError, ValueError, subprocess.SubprocessError) as exc:
        raise DevelopmentFdHandoffCanaryError(
            "descriptor handoff canary failed closed"
        ) from exc
    finally:
        if executable_descriptor is not None:
            os.close(executable_descriptor)
        if handoff_descriptor is not None:
            os.close(handoff_descriptor)
        if snapshot_duplicate is not None:
            os.close(snapshot_duplicate)


def verify_development_fd_handoff_canary_evidence(
    evidence: object,
) -> bool:
    """Return ``True`` only for exact, internally consistent canary evidence."""

    if type(evidence) is not DevelopmentFdHandoffCanaryEvidence:
        return False
    try:
        evidence.__post_init__()
    except (DevelopmentFdHandoffCanaryError, OSError, TypeError, ValueError):
        return False
    return True


__all__ = [
    "DEVELOPMENT_FD_HANDOFF_CANARY_ALGORITHM",
    "DEVELOPMENT_FD_HANDOFF_CANARY_KIND",
    "DEVELOPMENT_FD_HANDOFF_CANARY_SCHEMA_VERSION",
    "DEVELOPMENT_FD_HANDOFF_CANARY_VERSION",
    "DevelopmentFdHandoffCanaryError",
    "DevelopmentFdHandoffCanaryEvidence",
    "HANDOFF_DESCRIPTOR_FLOOR",
    "HANDOFF_HELPER_SOURCE_SHA256",
    "run_development_fd_handoff_canary",
    "verify_development_fd_handoff_canary_evidence",
]
