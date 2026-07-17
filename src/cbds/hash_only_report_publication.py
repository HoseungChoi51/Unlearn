"""Hardened no-replace publication for bounded hash-only reports.

This module is deliberately limited to publishing immutable bytes as one
mode-0644, link-count-one regular file.  It never follows a symbolic link in
the report path, and it accepts a pre-existing report only when a stable,
bounded read proves exact byte identity.

Publication stages a high-entropy exclusive temporary file and uses a hard
link as the atomic no-replace operation.  Temporary and final names are
authenticated against the staged inode before cleanup.  POSIX has no
fd-relative conditional unlink-by-inode operation, so the cleanup
stat-to-unlink steps cannot protect against an actively concurrent same-name
replacement in those tiny intervals; callers must serialize writers to one
report directory.

There is one intentionally conservative failure case.  If the first
``fstat`` immediately after exclusive temporary creation fails, the open
descriptor is closed but the temporary name is left untouched.  Without that
descriptor metadata the name cannot be authenticated as the inode just
created, and unlinking it could delete a concurrent replacement.  The
high-entropy name and initial mode 0600 bound the resulting orphan.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Final


_READ_CHUNK_BYTES: Final[int] = 64 * 1024
_TEMPORARY_TOKEN_BYTES: Final[int] = 16
_MAX_TEMPORARY_PREFIX_UTF8_BYTES: Final[int] = 128
_TEMPORARY_PREFIX_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9._-]+\Z"
)


class HashOnlyReportPublicationError(ValueError):
    """Raised when a report cannot be read or published safely."""


def _fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
    )


def _content_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    """Return inode/content metadata unaffected by hard-link operations."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _require_regular_shape(
    metadata: os.stat_result,
    *,
    size: int,
    link_count: int,
    label: str,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o644
        or metadata.st_size != size
        or metadata.st_nlink != link_count
    ):
        raise HashOnlyReportPublicationError(
            f"{label} must be one exact mode-0644 regular file with "
            f"size {size} and link count {link_count}"
        )


def _directory_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", None)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if directory is None or nofollow is None:
        raise HashOnlyReportPublicationError(
            "platform lacks no-follow directory opens"
        )
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | directory | nofollow


def _open_parent_directory(path: Path, *, create: bool) -> tuple[int, str]:
    """Open every parent component without following a symbolic link."""

    try:
        absolute = Path(os.path.abspath(os.fspath(path)))
    except (TypeError, ValueError, OSError) as exc:
        raise HashOnlyReportPublicationError("report path is invalid") from exc
    if not absolute.name or absolute.name in {".", ".."}:
        raise HashOnlyReportPublicationError(
            "report path has no canonical file name"
        )
    try:
        descriptor = os.open("/", _directory_flags())
    except OSError as exc:
        raise HashOnlyReportPublicationError(
            "filesystem root cannot be opened safely"
        ) from exc
    try:
        for component in absolute.parent.parts[1:]:
            if create:
                try:
                    os.mkdir(component, 0o755, dir_fd=descriptor)
                except OSError as exc:
                    if exc.errno != errno.EEXIST:
                        raise HashOnlyReportPublicationError(
                            "report parent cannot be created safely"
                        ) from exc
            child: int | None = None
            try:
                named_before = os.stat(
                    component,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                child = os.open(
                    component,
                    _directory_flags(),
                    dir_fd=descriptor,
                )
                opened = os.fstat(child)
                named_after = os.stat(
                    component,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                if child is not None:
                    os.close(child)
                if not create:
                    raise
                raise HashOnlyReportPublicationError(
                    "report parent disappeared while it was opened"
                )
            except OSError as exc:
                if child is not None:
                    os.close(child)
                raise HashOnlyReportPublicationError(
                    "report parent cannot be opened safely: "
                    f"{type(exc).__name__}"
                ) from exc
            if child is None:
                raise HashOnlyReportPublicationError(
                    "report parent open produced no descriptor"
                )
            if (
                not stat.S_ISDIR(opened.st_mode)
                or _fingerprint(named_before) != _fingerprint(opened)
                or _fingerprint(named_after) != _fingerprint(opened)
            ):
                os.close(child)
                raise HashOnlyReportPublicationError(
                    "report parent changed while it was opened"
                )
            os.close(descriptor)
            descriptor = child
        return descriptor, absolute.name
    except BaseException:
        os.close(descriptor)
        raise


def _assert_parent_reachable(
    path: Path,
    parent_descriptor: int,
    name: str,
) -> None:
    """Require the caller path to still resolve to the pinned parent inode."""

    reopened: int | None = None
    try:
        try:
            reopened, reopened_name = _open_parent_directory(
                path,
                create=False,
            )
        except (FileNotFoundError, HashOnlyReportPublicationError) as exc:
            raise HashOnlyReportPublicationError(
                "report parent is no longer reachable at the caller path"
            ) from exc
        try:
            pinned = os.fstat(parent_descriptor)
            observed = os.fstat(reopened)
        except OSError as exc:
            raise HashOnlyReportPublicationError(
                "report parent identity cannot be revalidated"
            ) from exc
        if reopened_name != name or not _same_inode(pinned, observed):
            raise HashOnlyReportPublicationError(
                "report parent is no longer reachable at the caller path"
            )
    finally:
        if reopened is not None:
            os.close(reopened)


def _read_existing_regular_snapshot_at(
    parent_descriptor: int,
    name: str,
    maximum_bytes: int,
) -> tuple[bytes, os.stat_result] | None:
    """Read one stable ordinary entry below an already pinned parent."""

    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise HashOnlyReportPublicationError(
            "platform lacks no-follow report opens"
        )
    try:
        named_before = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise HashOnlyReportPublicationError(
            "existing report path cannot be inspected safely"
        ) from exc
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | nofollow,
            dir_fd=parent_descriptor,
        )
    except OSError as exc:
        raise HashOnlyReportPublicationError(
            "existing report cannot be opened safely: "
            f"{type(exc).__name__}"
        ) from exc

    before: os.stat_result
    after: os.stat_result
    try:
        try:
            before = os.fstat(descriptor)
        except OSError as exc:
            raise HashOnlyReportPublicationError(
                "existing report descriptor cannot be inspected"
            ) from exc
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o644
            or _fingerprint(named_before) != _fingerprint(before)
        ):
            raise HashOnlyReportPublicationError(
                "existing report must be one stable mode-0644 "
                "link-count-one regular file"
            )
        if before.st_size > maximum_bytes:
            raise HashOnlyReportPublicationError(
                "existing report exceeds the configured byte bound"
            )
        payload = bytearray()
        remaining = before.st_size
        try:
            while remaining:
                chunk = os.read(
                    descriptor,
                    min(_READ_CHUNK_BYTES, remaining),
                )
                if not chunk:
                    raise HashOnlyReportPublicationError(
                        "existing report ended while being read"
                    )
                payload.extend(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise HashOnlyReportPublicationError(
                    "existing report grew while being read"
                )
            after = os.fstat(descriptor)
        except HashOnlyReportPublicationError:
            raise
        except OSError as exc:
            raise HashOnlyReportPublicationError(
                "existing report cannot be read stably"
            ) from exc
    finally:
        os.close(descriptor)

    try:
        named_after = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise HashOnlyReportPublicationError(
            "existing report path changed while being read"
        ) from exc
    if (
        _fingerprint(before) != _fingerprint(after)
        or _fingerprint(after) != _fingerprint(named_after)
    ):
        raise HashOnlyReportPublicationError(
            "existing report changed while being read"
        )
    return bytes(payload), after


def _read_existing_regular_at(
    parent_descriptor: int,
    name: str,
    maximum_bytes: int,
) -> bytes | None:
    snapshot = _read_existing_regular_snapshot_at(
        parent_descriptor,
        name,
        maximum_bytes,
    )
    return None if snapshot is None else snapshot[0]


def read_existing_regular(
    path: Path,
    max_bytes: int,
) -> bytes | None:
    """Read one bounded stable report without following any path component."""

    if not isinstance(path, Path):
        raise HashOnlyReportPublicationError(
            "report read requires a Path"
        )
    if type(max_bytes) is not int or max_bytes < 0:
        raise HashOnlyReportPublicationError(
            "max_bytes must be a nonnegative exact integer"
        )
    try:
        parent, name = _open_parent_directory(path, create=False)
    except FileNotFoundError:
        return None
    try:
        _assert_parent_reachable(path, parent, name)
        payload = _read_existing_regular_at(parent, name, max_bytes)
        _assert_parent_reachable(path, parent, name)
        return payload
    finally:
        os.close(parent)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        try:
            written = os.write(descriptor, view)
        except OSError as exc:
            raise HashOnlyReportPublicationError(
                "staged report cannot be written completely"
            ) from exc
        if written <= 0:
            raise HashOnlyReportPublicationError(
                "short write while publishing hash-only report"
            )
        view = view[written:]


def _fsync(descriptor: int, label: str) -> None:
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise HashOnlyReportPublicationError(
            f"{label} cannot be synchronized durably"
        ) from exc


def _authenticate_staged_before_link(
    parent_descriptor: int,
    temporary_name: str,
    opened: os.stat_result,
    payload_size: int,
) -> os.stat_result:
    """Bind the staged directory entry to the just-written descriptor."""

    try:
        named = os.stat(
            temporary_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise HashOnlyReportPublicationError(
            "staged report path cannot be authenticated"
        ) from exc
    _require_regular_shape(
        opened,
        size=payload_size,
        link_count=1,
        label="staged report descriptor",
    )
    if _fingerprint(named) != _fingerprint(opened):
        raise HashOnlyReportPublicationError(
            "staged report path differs from its written descriptor"
        )
    return named


def _authenticate_staged_after_link(
    parent_descriptor: int,
    temporary_name: str,
    name: str,
    staged: os.stat_result,
    payload_size: int,
) -> None:
    """Require the temporary and final names to be the sole staged links."""

    try:
        temporary = os.stat(
            temporary_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        final = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise HashOnlyReportPublicationError(
            "linked staged report cannot be authenticated"
        ) from exc
    _require_regular_shape(
        temporary,
        size=payload_size,
        link_count=2,
        label="linked staged report",
    )
    _require_regular_shape(
        final,
        size=payload_size,
        link_count=2,
        label="published staged report",
    )
    if (
        _fingerprint(temporary) != _fingerprint(final)
        or not _same_inode(temporary, staged)
        or _content_fingerprint(temporary)
        != _content_fingerprint(staged)
    ):
        raise HashOnlyReportPublicationError(
            "linked report names or content metadata differ from staging"
        )


def _authenticate_final_exact(
    parent_descriptor: int,
    name: str,
    payload: bytes,
    expected: os.stat_result,
    *,
    staged: bool,
) -> None:
    """Read back one exact stable final, preserving pre-existing entries."""

    snapshot = _read_existing_regular_snapshot_at(
        parent_descriptor,
        name,
        len(payload),
    )
    if snapshot is None:
        raise HashOnlyReportPublicationError(
            "final report disappeared before exact validation"
        )
    observed_payload, observed = snapshot
    if observed_payload != payload:
        raise HashOnlyReportPublicationError(
            "final report differs from deterministic generation"
        )
    if staged:
        matches = (
            _same_inode(observed, expected)
            and _content_fingerprint(observed)
            == _content_fingerprint(expected)
        )
    else:
        matches = _fingerprint(observed) == _fingerprint(expected)
    if not matches:
        raise HashOnlyReportPublicationError(
            "final report identity or metadata changed during publication"
        )


def _unlink_published_if_same(
    parent_descriptor: int,
    name: str,
    expected: os.stat_result,
) -> None:
    """Remove a failed publication only when it still names the staged inode.

    The no-follow stat preserves a replacement already visible at
    authentication time.  POSIX has no conditional unlink-by-inode operation,
    so an actively concurrent replacement in the following stat-to-unlink
    interval remains outside this helper's guarantee.
    """

    try:
        observed = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    except OSError as exc:
        raise HashOnlyReportPublicationError(
            "cannot authenticate displaced published report"
        ) from exc
    if not _same_inode(observed, expected):
        raise HashOnlyReportPublicationError(
            "displaced published report no longer names the staged inode"
        )
    try:
        os.unlink(name, dir_fd=parent_descriptor)
    except OSError as exc:
        raise HashOnlyReportPublicationError(
            "cannot remove displaced published report"
        ) from exc


def _unlink_temporary_if_same(
    parent_descriptor: int,
    temporary_name: str,
    created: os.stat_result,
    *,
    fail_closed: bool,
) -> bool:
    """Remove only a temporary name still resolving to the created inode.

    The no-follow stat preserves a replacement already visible at
    authentication time.  As with final cleanup, POSIX cannot make the
    following stat-to-unlink interval conditional on inode identity.
    """

    try:
        observed = os.stat(
            temporary_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError as exc:
        if fail_closed:
            raise HashOnlyReportPublicationError(
                "staged report name disappeared before cleanup"
            ) from exc
        return False
    except OSError as exc:
        if fail_closed:
            raise HashOnlyReportPublicationError(
                "staged report name cannot be authenticated for cleanup"
            ) from exc
        return False
    if not _same_inode(observed, created):
        if fail_closed:
            raise HashOnlyReportPublicationError(
                "staged report name no longer resolves to the created inode"
            )
        return False
    try:
        os.unlink(temporary_name, dir_fd=parent_descriptor)
    except OSError as exc:
        if fail_closed:
            raise HashOnlyReportPublicationError(
                "authenticated staged report cannot be removed"
            ) from exc
        return False
    return True


def _validate_temporary_prefix(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or _TEMPORARY_PREFIX_RE.fullmatch(value) is None
    ):
        raise HashOnlyReportPublicationError(
            "temporary_prefix must be a nonempty safe ASCII file-name prefix"
        )
    if len(value.encode("ascii")) > _MAX_TEMPORARY_PREFIX_UTF8_BYTES:
        raise HashOnlyReportPublicationError(
            "temporary_prefix exceeds its byte limit"
        )
    return value


def atomic_publish_noreplace(
    path: Path,
    payload: bytes,
    temporary_prefix: str,
) -> None:
    """Atomically publish bytes without replacing a pre-existing path.

    An exact stable pre-existing report is accepted idempotently.  A differing
    or unsafe pre-existing entry is preserved and rejected.

    If the immediate post-open ``fstat`` of the exclusive temporary descriptor
    fails, the descriptor is closed and the unauthenticated temporary name is
    deliberately retained.  See the module-level safety note.
    """

    if not isinstance(path, Path) or type(payload) is not bytes:
        raise HashOnlyReportPublicationError(
            "publication requires a Path and immutable bytes"
        )
    selected_prefix = _validate_temporary_prefix(temporary_prefix)
    parent, name = _open_parent_directory(path, create=True)
    descriptor: int | None = None
    descriptor_open = False
    temporary_exists = False
    created_temporary_metadata: os.stat_result | None = None
    temporary_metadata: os.stat_result | None = None
    existing_metadata: os.stat_result | None = None
    published = False
    temporary_name = (
        f"{selected_prefix}"
        f"{secrets.token_hex(_TEMPORARY_TOKEN_BYTES)}.tmp"
    )
    try:
        _assert_parent_reachable(path, parent, name)
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise HashOnlyReportPublicationError(
                "platform lacks no-follow temporary opens"
            )
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | nofollow,
                0o600,
                dir_fd=parent,
            )
        except OSError as exc:
            raise HashOnlyReportPublicationError(
                "report staging file cannot be created safely"
            ) from exc
        descriptor_open = True
        temporary_exists = True
        try:
            created_temporary_metadata = os.fstat(descriptor)
        except OSError as exc:
            raise HashOnlyReportPublicationError(
                "created staging inode cannot be authenticated; "
                "its high-entropy temporary name was left untouched"
            ) from exc

        try:
            os.fchmod(descriptor, 0o644)
            _write_all(descriptor, payload)
            _fsync(descriptor, "staged report")
            written_metadata = os.fstat(descriptor)
        except HashOnlyReportPublicationError:
            raise
        except OSError as exc:
            raise HashOnlyReportPublicationError(
                "staged report cannot be finalized durably"
            ) from exc
        if not _same_inode(
            written_metadata,
            created_temporary_metadata,
        ):
            raise HashOnlyReportPublicationError(
                "written report descriptor differs from its created inode"
            )
        temporary_metadata = _authenticate_staged_before_link(
            parent,
            temporary_name,
            written_metadata,
            len(payload),
        )
        os.close(descriptor)
        descriptor_open = False
        descriptor = None

        try:
            os.link(
                temporary_name,
                name,
                src_dir_fd=parent,
                dst_dir_fd=parent,
                follow_symlinks=False,
            )
        except FileExistsError:
            snapshot = _read_existing_regular_snapshot_at(
                parent,
                name,
                len(payload),
            )
            if snapshot is None or snapshot[0] != payload:
                raise HashOnlyReportPublicationError(
                    "existing report differs from deterministic generation"
                )
            existing_metadata = snapshot[1]
        except OSError as exc:
            raise HashOnlyReportPublicationError(
                "staged report cannot be linked without replacement"
            ) from exc
        else:
            published = True

        try:
            if published:
                if temporary_metadata is None:
                    raise HashOnlyReportPublicationError(
                        "published report lacks authenticated staging metadata"
                    )
                _authenticate_staged_after_link(
                    parent,
                    temporary_name,
                    name,
                    temporary_metadata,
                    len(payload),
                )
                _fsync(parent, "report parent")
            _assert_parent_reachable(path, parent, name)
            if created_temporary_metadata is None:
                raise HashOnlyReportPublicationError(
                    "staged report lacks authenticated creation metadata"
                )
            _unlink_temporary_if_same(
                parent,
                temporary_name,
                created_temporary_metadata,
                fail_closed=True,
            )
            temporary_exists = False
            _fsync(parent, "report parent")
            if published:
                if temporary_metadata is None:
                    raise HashOnlyReportPublicationError(
                        "published report lacks authenticated staging metadata"
                    )
                _authenticate_final_exact(
                    parent,
                    name,
                    payload,
                    temporary_metadata,
                    staged=True,
                )
            elif existing_metadata is not None:
                _authenticate_final_exact(
                    parent,
                    name,
                    payload,
                    existing_metadata,
                    staged=False,
                )
            else:
                raise HashOnlyReportPublicationError(
                    "publication established neither a staged nor existing final"
                )
            _assert_parent_reachable(path, parent, name)
        except BaseException:
            if published and temporary_metadata is not None:
                _unlink_published_if_same(
                    parent,
                    name,
                    temporary_metadata,
                )
                _fsync(parent, "report parent")
            raise
    except HashOnlyReportPublicationError:
        raise
    except OSError as exc:
        raise HashOnlyReportPublicationError(
            "report publication failed during a filesystem operation"
        ) from exc
    finally:
        if descriptor_open and descriptor is not None:
            os.close(descriptor)
        if (
            temporary_exists
            and created_temporary_metadata is not None
        ):
            _unlink_temporary_if_same(
                parent,
                temporary_name,
                created_temporary_metadata,
                fail_closed=False,
            )
        try:
            _fsync(parent, "report parent")
        finally:
            os.close(parent)


__all__ = [
    "HashOnlyReportPublicationError",
    "atomic_publish_noreplace",
    "read_existing_regular",
]
