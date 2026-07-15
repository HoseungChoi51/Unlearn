#!/usr/bin/env python3
"""Emit the non-executing BashBench release-v1 audit as canonical JSON."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.bashbench_audit import (  # noqa: E402
    BashBenchSource,
    audit_bashbench_projection,
    canonical_json_bytes,
    validate_bashbench_audit_report,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Statically audit the six selected BashCoder-R1/BashBench release-v1 "
            "members without importing or executing upstream code."
        )
    )
    parser.add_argument(
        "projection",
        type=Path,
        help="directory containing the six required members at archive-relative paths",
    )
    arguments = parser.parse_args()
    report = audit_bashbench_projection(
        arguments.projection,
        source=BashBenchSource.release_v1(),
    )
    validate_bashbench_audit_report(
        report,
        require_authenticated_projection=True,
    )
    sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
