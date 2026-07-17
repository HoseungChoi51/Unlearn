#!/usr/bin/env python3
"""Build or check the hash-only additive seventh-tranche catalog report.

Catalog construction and validation live exclusively in
``cbds.executable_fixture_seventh_catalog``.  This script serializes only that
module's hash-only projection and atomically publishes it at a caller-selected
path; prompts, fixture inputs, paths, and trusted oracle bytes are never
written.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_fixture_seventh_catalog import (  # noqa: E402
    build_seventh_tranche_fixture_catalog,
)


class SeventhTrancheCatalogPublicationError(ValueError):
    """Raised when a report cannot be safely published without replacement."""


def canonical_seventh_tranche_catalog_bytes() -> bytes:
    """Return the central catalog's deterministic hash-only JSON projection."""

    catalog = build_seventh_tranche_fixture_catalog()
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


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write while publishing seventh-tranche report")
        view = view[written:]


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_publish_noreplace(path: Path, payload: bytes) -> None:
    """Atomically publish bytes without replacing a pre-existing path."""

    if not isinstance(path, Path) or type(payload) is not bytes:
        raise SeventhTrancheCatalogPublicationError(
            "publication requires a Path and immutable bytes"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    descriptor_open = True
    try:
        os.fchmod(descriptor, 0o644)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor_open = False
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != payload:
                raise SeventhTrancheCatalogPublicationError(
                    "existing report differs from deterministic generation"
                )
        else:
            _fsync_directory(path.parent)
    finally:
        if descriptor_open:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        _fsync_directory(path.parent)


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
    output = arguments.output.resolve()
    payload = canonical_seventh_tranche_catalog_bytes()
    if output.exists():
        if output.read_bytes() != payload:
            raise SystemExit(
                "existing seventh-tranche report differs from fresh generation"
            )
        return 0
    if arguments.check:
        raise SystemExit("seventh-tranche catalog report does not exist")
    try:
        atomic_publish_noreplace(output, payload)
    except SeventhTrancheCatalogPublicationError as exc:
        raise SystemExit(str(exc)) from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
