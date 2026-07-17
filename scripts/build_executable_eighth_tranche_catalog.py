#!/usr/bin/env python3
"""Build or check the hash-only additive eighth-tranche catalog report.

Catalog construction and validation live exclusively in
``cbds.executable_fixture_eighth_catalog``.  This script serializes only that
module's hash-only projection and publishes it without replacing an existing
path.  Prompts, fixture paths and bytes, oracle bytes, and answers are never
written to the report.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
from pathlib import Path
import secrets
import stat
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_fixture_eighth_catalog import (  # noqa: E402
    build_eighth_tranche_fixture_catalog,
)


class EighthTrancheCatalogPublicationError(ValueError):
    """Raised when a report cannot be safely published without replacement."""


def canonical_eighth_tranche_catalog_bytes() -> bytes:
    """Return the central catalog's deterministic hash-only JSON projection."""

    catalog = build_eighth_tranche_fixture_catalog()
    return (
        json.dumps(
            catalog.to_hash_only_record(),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


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
    """Return inode/content metadata that hard-link operations cannot change."""

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
        raise EighthTrancheCatalogPublicationError(
            f"{label} must be one exact mode-0644 regular file with "
            f"size {size} and link count {link_count}"
        )


def _directory_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", None)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if directory is None or nofollow is None:
        raise EighthTrancheCatalogPublicationError(
            "platform lacks no-follow directory opens"
        )
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | directory | nofollow


def _open_parent_directory(path: Path, *, create: bool) -> tuple[int, str]:
    """Open every parent component without following a symbolic link."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.name or absolute.name in {".", ".."}:
        raise EighthTrancheCatalogPublicationError(
            "report path has no canonical file name"
        )
    descriptor = os.open("/", _directory_flags())
    try:
        for component in absolute.parent.parts[1:]:
            if create:
                try:
                    os.mkdir(component, 0o755, dir_fd=descriptor)
                except OSError as exc:
                    if exc.errno != errno.EEXIST:
                        raise EighthTrancheCatalogPublicationError(
                            "report parent cannot be created safely"
                        ) from exc
            child: int | None = None
            try:
                named_before = os.stat(
                    component, dir_fd=descriptor, follow_symlinks=False
                )
                child = os.open(
                    component, _directory_flags(), dir_fd=descriptor
                )
                opened = os.fstat(child)
                named_after = os.stat(
                    component, dir_fd=descriptor, follow_symlinks=False
                )
            except FileNotFoundError:
                if child is not None:
                    os.close(child)
                raise
            except OSError as exc:
                if child is not None:
                    os.close(child)
                raise EighthTrancheCatalogPublicationError(
                    f"report parent cannot be opened safely: {type(exc).__name__}"
                ) from exc
            if child is None:
                raise EighthTrancheCatalogPublicationError(
                    "report parent open produced no descriptor"
                )
            if (
                not stat.S_ISDIR(opened.st_mode)
                or _fingerprint(named_before) != _fingerprint(opened)
                or _fingerprint(named_after) != _fingerprint(opened)
            ):
                os.close(child)
                raise EighthTrancheCatalogPublicationError(
                    "report parent changed while it was opened"
                )
            os.close(descriptor)
            descriptor = child
        return descriptor, absolute.name
    except BaseException:
        os.close(descriptor)
        raise


def _assert_parent_reachable(path: Path, parent_descriptor: int, name: str) -> None:
    """Require the caller path to still resolve to the pinned parent inode."""

    reopened: int | None = None
    try:
        reopened, reopened_name = _open_parent_directory(path, create=False)
        if (
            reopened_name != name
            or not _same_inode(
                os.fstat(parent_descriptor), os.fstat(reopened)
            )
        ):
            raise EighthTrancheCatalogPublicationError(
                "report parent is no longer reachable at the caller path"
            )
    except FileNotFoundError as exc:
        raise EighthTrancheCatalogPublicationError(
            "report parent is no longer reachable at the caller path"
        ) from exc
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
        raise EighthTrancheCatalogPublicationError(
            "platform lacks no-follow report opens"
        )
    try:
        named_before = os.stat(
            name, dir_fd=parent_descriptor, follow_symlinks=False
        )
    except FileNotFoundError:
        return None
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
        raise EighthTrancheCatalogPublicationError(
            f"existing report cannot be opened safely: {type(exc).__name__}"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o644
            or _fingerprint(named_before) != _fingerprint(before)
        ):
            raise EighthTrancheCatalogPublicationError(
                "existing report must be one stable mode-0644 "
                "link-count-one regular file"
            )
        if before.st_size > maximum_bytes:
            raise EighthTrancheCatalogPublicationError(
                "existing report exceeds deterministic generation"
            )
        payload = bytearray()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise EighthTrancheCatalogPublicationError(
                    "existing report ended while being read"
                )
            payload.extend(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise EighthTrancheCatalogPublicationError(
                "existing report grew while being read"
            )
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        named_after = os.stat(
            name, dir_fd=parent_descriptor, follow_symlinks=False
        )
    except OSError as exc:
        raise EighthTrancheCatalogPublicationError(
            "existing report path changed while being read"
        ) from exc
    if (
        _fingerprint(before) != _fingerprint(after)
        or _fingerprint(after) != _fingerprint(named_after)
    ):
        raise EighthTrancheCatalogPublicationError(
            "existing report changed while being read"
        )
    return bytes(payload), after


def _read_existing_regular_at(
    parent_descriptor: int,
    name: str,
    maximum_bytes: int,
) -> bytes | None:
    snapshot = _read_existing_regular_snapshot_at(
        parent_descriptor, name, maximum_bytes
    )
    return None if snapshot is None else snapshot[0]


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
        raise EighthTrancheCatalogPublicationError(
            "staged report path cannot be authenticated"
        ) from exc
    _require_regular_shape(
        opened,
        size=payload_size,
        link_count=1,
        label="staged report descriptor",
    )
    if _fingerprint(named) != _fingerprint(opened):
        raise EighthTrancheCatalogPublicationError(
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
        raise EighthTrancheCatalogPublicationError(
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
        or _content_fingerprint(temporary) != _content_fingerprint(staged)
    ):
        raise EighthTrancheCatalogPublicationError(
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
        parent_descriptor, name, len(payload)
    )
    if snapshot is None:
        raise EighthTrancheCatalogPublicationError(
            "final report disappeared before exact validation"
        )
    observed_payload, observed = snapshot
    if observed_payload != payload:
        raise EighthTrancheCatalogPublicationError(
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
        raise EighthTrancheCatalogPublicationError(
            "final report identity or metadata changed during publication"
        )


def _read_existing_regular(path: Path, maximum_bytes: int) -> bytes | None:
    """Read one stable report without following any path component."""

    try:
        parent, name = _open_parent_directory(path, create=False)
    except FileNotFoundError:
        return None
    try:
        _assert_parent_reachable(path, parent, name)
        payload = _read_existing_regular_at(parent, name, maximum_bytes)
        _assert_parent_reachable(path, parent, name)
        return payload
    finally:
        os.close(parent)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write while publishing eighth-tranche report")
        view = view[written:]


def _unlink_published_if_same(
    parent_descriptor: int,
    name: str,
    expected: os.stat_result,
) -> None:
    """Best-effort cleanup of a final authenticated as our staged inode.

    The no-follow stat rejects a replacement already visible at authentication
    time.  POSIX has no fd-relative conditional unlink-by-inode operation, so a
    same-name replacement in the remaining stat-to-unlink interval is outside
    this helper's guarantee.  Callers must not treat it as safe against an
    actively concurrent writer in the same directory.
    """

    try:
        observed = os.stat(
            name, dir_fd=parent_descriptor, follow_symlinks=False
        )
    except FileNotFoundError:
        return
    except OSError as exc:
        raise EighthTrancheCatalogPublicationError(
            "cannot authenticate displaced published report"
        ) from exc
    if not _same_inode(observed, expected):
        raise EighthTrancheCatalogPublicationError(
            "displaced published report no longer names the staged inode"
        )
    try:
        os.unlink(name, dir_fd=parent_descriptor)
    except OSError as exc:
        raise EighthTrancheCatalogPublicationError(
            "cannot remove displaced published report"
        ) from exc


def _unlink_temporary_if_same(
    parent_descriptor: int,
    temporary_name: str,
    created: os.stat_result,
    *,
    fail_closed: bool,
) -> bool:
    """Remove only a temp name still resolving to the created inode.

    The no-follow stat authenticates the name immediately before unlink.  POSIX
    does not provide an fd-relative unlink-by-inode primitive, so a same-name
    replacement in the remaining stat-to-unlink interval is outside this
    helper's guarantee.
    """

    try:
        observed = os.stat(
            temporary_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError as exc:
        if fail_closed:
            raise EighthTrancheCatalogPublicationError(
                "staged report name disappeared before cleanup"
            ) from exc
        return False
    except OSError as exc:
        if fail_closed:
            raise EighthTrancheCatalogPublicationError(
                "staged report name cannot be authenticated for cleanup"
            ) from exc
        return False
    if not _same_inode(observed, created):
        if fail_closed:
            raise EighthTrancheCatalogPublicationError(
                "staged report name no longer resolves to the created inode"
            )
        return False
    try:
        os.unlink(temporary_name, dir_fd=parent_descriptor)
    except OSError as exc:
        if fail_closed:
            raise EighthTrancheCatalogPublicationError(
                "authenticated staged report cannot be removed"
            ) from exc
        return False
    return True


def atomic_publish_noreplace(path: Path, payload: bytes) -> None:
    """Atomically publish bytes without replacing a pre-existing path."""

    if not isinstance(path, Path) or type(payload) is not bytes:
        raise EighthTrancheCatalogPublicationError(
            "publication requires a Path and immutable bytes"
        )
    parent, name = _open_parent_directory(path, create=True)
    try:
        _assert_parent_reachable(path, parent, name)
    except BaseException:
        os.close(parent)
        raise
    temporary_name = f".cbds-eighth-{secrets.token_hex(16)}.tmp"
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        os.close(parent)
        raise EighthTrancheCatalogPublicationError(
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
        os.close(parent)
        raise EighthTrancheCatalogPublicationError(
            "report staging file cannot be created safely"
        ) from exc
    try:
        created_temporary_metadata = os.fstat(descriptor)
    except OSError as exc:
        os.close(descriptor)
        os.close(parent)
        raise EighthTrancheCatalogPublicationError(
            "created report staging inode cannot be captured"
        ) from exc
    descriptor_open = True
    temporary_exists = True
    temporary_metadata: os.stat_result | None = None
    existing_metadata: os.stat_result | None = None
    published = False
    try:
        os.fchmod(descriptor, 0o644)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        written_metadata = os.fstat(descriptor)
        if not _same_inode(written_metadata, created_temporary_metadata):
            raise EighthTrancheCatalogPublicationError(
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
                parent, name, len(payload)
            )
            if snapshot is None or snapshot[0] != payload:
                raise EighthTrancheCatalogPublicationError(
                    "existing report differs from deterministic generation"
                )
            existing_metadata = snapshot[1]
        else:
            published = True
        try:
            if published:
                if temporary_metadata is None:
                    raise EighthTrancheCatalogPublicationError(
                        "published report lacks authenticated staging metadata"
                    )
                _authenticate_staged_after_link(
                    parent,
                    temporary_name,
                    name,
                    temporary_metadata,
                    len(payload),
                )
                os.fsync(parent)
            _assert_parent_reachable(path, parent, name)
            _unlink_temporary_if_same(
                parent,
                temporary_name,
                created_temporary_metadata,
                fail_closed=True,
            )
            temporary_exists = False
            os.fsync(parent)
            if published:
                if temporary_metadata is None:
                    raise EighthTrancheCatalogPublicationError(
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
                raise EighthTrancheCatalogPublicationError(
                    "publication established neither a staged nor existing final"
                )
            _assert_parent_reachable(path, parent, name)
        except BaseException:
            if published and temporary_metadata is not None:
                # This is failure cleanup under the documented no-concurrent-
                # same-name-writer boundary, not an atomic conditional unlink.
                _unlink_published_if_same(parent, name, temporary_metadata)
                os.fsync(parent)
            raise
    finally:
        if descriptor_open:
            os.close(descriptor)
        if temporary_exists:
            _unlink_temporary_if_same(
                parent,
                temporary_name,
                created_temporary_metadata,
                fail_closed=False,
            )
        try:
            os.fsync(parent)
        finally:
            os.close(parent)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="caller-selected path for the hash-only JSON report",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="require the existing output to equal a fresh deterministic rebuild",
    )
    arguments = parser.parse_args(argv)
    output = arguments.output.absolute()
    payload = canonical_eighth_tranche_catalog_bytes()
    try:
        existing = _read_existing_regular(output, len(payload))
    except EighthTrancheCatalogPublicationError as exc:
        raise SystemExit(str(exc)) from exc
    if existing is not None:
        if existing != payload:
            raise SystemExit(
                "existing eighth-tranche report differs from fresh generation"
            )
        return 0
    if arguments.check:
        raise SystemExit("eighth-tranche catalog report does not exist")
    try:
        atomic_publish_noreplace(output, payload)
    except EighthTrancheCatalogPublicationError as exc:
        raise SystemExit(str(exc)) from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
