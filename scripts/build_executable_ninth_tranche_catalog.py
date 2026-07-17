#!/usr/bin/env python3
"""Build or check the bounded hash-only ninth-tranche catalog report.

Catalog construction and validation live in
``cbds.executable_fixture_ninth_catalog``.  This script serializes only that
module's public hash projection and delegates no-replace publication to
``cbds.hash_only_report_publication``.  It never writes prompts, fixture paths
or bytes, oracle answers, or execution authority, and it never executes a
candidate.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_fixture_ninth_catalog import (  # noqa: E402
    build_ninth_tranche_fixture_catalog,
)
from cbds.hash_only_report_publication import (  # noqa: E402
    HashOnlyReportPublicationError,
    atomic_publish_noreplace as _shared_atomic_publish_noreplace,
    read_existing_regular as _shared_read_existing_regular,
)


NINTH_TRANCHE_REPORT_MAXIMUM_BYTES = 1024 * 1024
NINTH_TRANCHE_TEMPORARY_PREFIX = ".cbds-ninth-"
NinthTrancheCatalogPublicationError = HashOnlyReportPublicationError

_AUTHORITY_FIELDS = (
    "sealed",
    "independent_human_review_attested",
    "candidate_execution_authorized",
    "model_selection_eligible",
    "claim_authorized",
)


def canonical_ninth_tranche_catalog_bytes() -> bytes:
    """Return the central catalog's deterministic bounded hash-only JSON."""

    record = build_ninth_tranche_fixture_catalog().to_hash_only_record()
    if record.get("public_method_development") is not True or any(
        record.get(field) is not False for field in _AUTHORITY_FIELDS
    ):
        raise NinthTrancheCatalogPublicationError(
            "catalog authority boundary differs from the public report contract"
        )
    payload = (
        json.dumps(
            record,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")
    if len(payload) > NINTH_TRANCHE_REPORT_MAXIMUM_BYTES:
        raise NinthTrancheCatalogPublicationError(
            "ninth-tranche report exceeds its fixed byte bound"
        )
    return payload


def read_existing_report(path: Path) -> bytes | None:
    """Read one existing report through the shared bounded no-follow reader."""

    return _shared_read_existing_regular(
        path,
        NINTH_TRANCHE_REPORT_MAXIMUM_BYTES,
    )


def atomic_publish_noreplace(path: Path, payload: bytes) -> None:
    """Delegate bounded immutable publication to the shared hardened helper."""

    if type(payload) is bytes and len(payload) > NINTH_TRANCHE_REPORT_MAXIMUM_BYTES:
        raise NinthTrancheCatalogPublicationError(
            "ninth-tranche report exceeds its fixed byte bound"
        )
    _shared_atomic_publish_noreplace(
        path,
        payload,
        NINTH_TRANCHE_TEMPORARY_PREFIX,
    )


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
    payload = canonical_ninth_tranche_catalog_bytes()
    try:
        existing = read_existing_report(output)
    except NinthTrancheCatalogPublicationError as exc:
        raise SystemExit(str(exc)) from exc
    if existing is not None:
        if existing != payload:
            raise SystemExit(
                "existing ninth-tranche report differs from fresh generation"
            )
        return 0
    if arguments.check:
        raise SystemExit("ninth-tranche catalog report does not exist")
    try:
        atomic_publish_noreplace(output, payload)
    except NinthTrancheCatalogPublicationError as exc:
        raise SystemExit(str(exc)) from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
