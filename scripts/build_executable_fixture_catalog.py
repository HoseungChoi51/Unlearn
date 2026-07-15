#!/usr/bin/env python3
"""Rebuild or check the hash-only first-tranche fixture catalog manifest."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_fixture_catalog import (  # noqa: E402
    build_first_tranche_fixture_catalog,
)
from cbds.executable_static_registry import (  # noqa: E402
    build_public_method_development_registry,
)


DEFAULT_OUTPUT = ROOT / "reports" / "executable-first-tranche" / "manifest.json"


def _canonical_manifest_bytes() -> bytes:
    registry = build_public_method_development_registry()
    catalog = build_first_tranche_fixture_catalog(registry)
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


def _write_new(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o644,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while publishing catalog manifest")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="require the existing output to equal a fresh deterministic rebuild",
    )
    arguments = parser.parse_args(argv)
    output = arguments.output.resolve()
    payload = _canonical_manifest_bytes()
    if output.exists():
        if output.read_bytes() != payload:
            raise SystemExit("existing catalog manifest differs from fresh generation")
        return 0
    if arguments.check:
        raise SystemExit("catalog manifest does not exist")
    _write_new(output, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
