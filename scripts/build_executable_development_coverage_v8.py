#!/usr/bin/env python3
"""Build or check the immutable v8 coverage and v7-to-v8 migration locks."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_development_coverage_v7_to_v8_migration import (  # noqa: E402
    COVERAGE_V7_TO_V8_MIGRATION_CONFIG_RELATIVE_PATH,
    MAXIMUM_COVERAGE_V7_TO_V8_MIGRATION_CONFIG_BYTES,
    executable_development_coverage_v7_to_v8_migration_config_bytes,
)
from cbds.executable_development_coverage_v8 import (  # noqa: E402
    COVERAGE_V8_CONFIG_RELATIVE_PATH,
    MAXIMUM_COVERAGE_V8_CONFIG_BYTES,
    executable_development_coverage_v8_config_bytes,
)
from cbds.hash_only_report_publication import (  # noqa: E402
    HashOnlyReportPublicationError,
    atomic_publish_noreplace,
    read_existing_regular,
)


def _check_exact(path: Path, payload: bytes, maximum_bytes: int) -> None:
    existing = read_existing_regular(path, maximum_bytes)
    if existing != payload:
        raise HashOnlyReportPublicationError(
            f"checked artifact differs or is absent: {path}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--coverage-output",
        type=Path,
        default=ROOT / COVERAGE_V8_CONFIG_RELATIVE_PATH,
    )
    parser.add_argument(
        "--migration-output",
        type=Path,
        default=(
            ROOT / COVERAGE_V7_TO_V8_MIGRATION_CONFIG_RELATIVE_PATH
        ),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="require both existing artifacts to equal the central builders",
    )
    arguments = parser.parse_args(argv)
    coverage = executable_development_coverage_v8_config_bytes()
    migration = (
        executable_development_coverage_v7_to_v8_migration_config_bytes()
    )
    if arguments.check:
        _check_exact(
            arguments.coverage_output,
            coverage,
            MAXIMUM_COVERAGE_V8_CONFIG_BYTES,
        )
        _check_exact(
            arguments.migration_output,
            migration,
            MAXIMUM_COVERAGE_V7_TO_V8_MIGRATION_CONFIG_BYTES,
        )
    else:
        atomic_publish_noreplace(
            arguments.coverage_output,
            coverage,
            ".cbds-coverage-v8-",
        )
        atomic_publish_noreplace(
            arguments.migration_output,
            migration,
            ".cbds-coverage-v7-to-v8-migration-",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
