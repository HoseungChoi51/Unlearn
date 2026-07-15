"""Deterministic CSV aggregation fixtures for executable method development."""

from __future__ import annotations

import csv
import io
import re
from typing import Final

from .executable_fixture_bundle import (
    ExecutableFixtureBundle,
    OracleOutputRecord,
    build_executable_fixture_bundle,
    build_trusted_fixture_oracle,
)
from .executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
    ExecutableFixtureProfile,
)
from .executable_static_types import CsvGroupTotalsParameters, ExecutableStaticTask
from .executable_workspace import (
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
)


OUTPUT_MODE: Final[int] = 0o644
OUTPUT_LIMIT: Final[int] = 256 * 1024
_INTEGER_RE: Final[re.Pattern[str]] = re.compile(r"-?[0-9]+\Z")
_LAYOUT_FIELDS: Final[dict[str, tuple[str, str, str]]] = {
    "category-amount-enabled": ("category", "amount", "enabled"),
    "enabled-category-amount": ("enabled", "category", "amount"),
    "amount-enabled-category": ("amount", "enabled", "category"),
    "category-enabled-amount": ("category", "enabled", "amount"),
}


class ExecutableFixtureCsvError(ValueError):
    """Raised when a CSV fixture cannot be derived from its actual bytes."""


def _validate_task_profile(
    task: object, profile: object
) -> tuple[ExecutableStaticTask, ExecutableFixtureProfile]:
    if (
        type(task) is not ExecutableStaticTask
        or task.family_id != "csv-group-totals"
        or type(task.parameters) is not CsvGroupTotalsParameters
    ):
        raise ExecutableFixtureCsvError(
            "task must be an exact csv-group-totals ExecutableStaticTask"
        )
    if type(profile) is not ExecutableFixtureProfile:
        raise ExecutableFixtureCsvError(
            "profile must be an exact ExecutableFixtureProfile"
        )
    try:
        task.__post_init__()
        profile.__post_init__()
    except (TypeError, ValueError) as exc:
        raise ExecutableFixtureCsvError(
            "task or profile failed closed-contract revalidation"
        ) from exc
    if profile not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        raise ExecutableFixtureCsvError(
            "profile is not public method-development data"
        )
    return task, profile


def _categories(profile: ExecutableFixtureProfile) -> tuple[str, str]:
    values = {
        "spaces-unicode": ("space category", '한글, "분류"'),
        "leading-dashes-globs": ("-leading", "glob[*]?"),
        "empty-duplicates": ("", "duplicate"),
        "symlinks-ordering": ("z-last", "a-first"),
        "partial-permissions": ("readable", "partial"),
    }
    try:
        return values[profile.profile_id]
    except KeyError as exc:
        raise ExecutableFixtureCsvError("unsupported fixture profile") from exc


def _encode_rows(
    layout: tuple[str, str, str], rows: tuple[dict[str, str], ...]
) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(layout)
    for record in rows:
        writer.writerow(tuple(record[field] for field in layout))
    return stream.getvalue().encode("utf-8")


def _fixture_inputs(
    profile: ExecutableFixtureProfile,
    parameters: CsvGroupTotalsParameters,
) -> tuple[InputFile | InputSymlink, ...]:
    first, second = _categories(profile)
    layout = _LAYOUT_FIELDS[parameters.layout]
    rows_a = (
        {"category": first, "amount": "5", "enabled": "yes"},
        {"category": first, "amount": "7", "enabled": "no"},
        {"category": second, "amount": "-2", "enabled": "yes"},
        {"category": second, "amount": "0", "enabled": "yes"},
        {"category": "ignored-invalid", "amount": "+3", "enabled": "yes"},
    )
    rows_b = (
        {"category": first, "amount": "3", "enabled": "yes"},
        {"category": second, "amount": "11", "enabled": "no"},
        {"category": "third", "amount": "2", "enabled": "yes"},
    )
    if profile.profile_id == "empty-duplicates":
        rows_b = (rows_a[0], *rows_b, rows_a[0])
    if profile.profile_id == "symlinks-ordering":
        rows_a = tuple(reversed(rows_a))
        rows_b = tuple(reversed(rows_b))
    valid_a = _encode_rows(layout, rows_a)
    valid_b = _encode_rows(layout, rows_b)
    header = ",".join(layout).encode("utf-8")
    malformed = header + b'\r\n"unterminated'
    wrong_header = b"wrong,amount,enabled\r\nignored,1,yes\r\n"
    return (
        InputFile("input/records/z records.csv", valid_a),
        InputFile("input/records/nested/a-records.csv", valid_b),
        InputFile("input/records/malformed.csv", malformed),
        InputFile("input/records/wrong-header.csv", wrong_header),
        InputFile("input/records/empty.csv", b""),
        InputFile("input/records/unreadable.csv", valid_a, 0o000),
        InputFile("input/records/not-selected.txt", valid_a),
        InputSymlink("input/records/link.csv", "z records.csv"),
    )


def _accepted_rows(
    inputs: tuple[InputFile | InputSymlink, ...],
    parameters: CsvGroupTotalsParameters,
) -> tuple[tuple[str, int, str], ...]:
    expected_header = list(_LAYOUT_FIELDS[parameters.layout])
    accepted: list[tuple[str, int, str]] = []
    for item in inputs:
        if (
            type(item) is not InputFile
            or item.mode & 0o444 == 0
            or not item.path.startswith("input/records/")
            or not item.path.rsplit("/", 1)[-1].endswith(".csv")
        ):
            continue
        try:
            text = item.content.decode("utf-8", errors="strict")
            rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
        except (UnicodeDecodeError, csv.Error):
            continue
        if not rows or rows[0] != expected_header:
            continue
        positions = {field: index for index, field in enumerate(expected_header)}
        for row in rows[1:]:
            if len(row) != 3:
                continue
            category = row[positions["category"]]
            amount_text = row[positions["amount"]]
            enabled = row[positions["enabled"]]
            if _INTEGER_RE.fullmatch(amount_text) is None:
                continue
            amount = int(amount_text, 10)
            predicate = parameters.predicate
            if predicate == "enabled-yes" and enabled != "yes":
                continue
            if predicate == "positive-amount" and amount <= 0:
                continue
            if predicate == "nonempty-category" and not category:
                continue
            if predicate == "enabled-and-positive" and (
                enabled != "yes" or amount <= 0
            ):
                continue
            accepted.append((category, amount, enabled))
    return tuple(accepted)


def _derive_output(
    inputs: tuple[InputFile | InputSymlink, ...],
    parameters: CsvGroupTotalsParameters,
) -> bytes:
    totals: dict[str, int] = {}
    for category, amount, _enabled in _accepted_rows(inputs, parameters):
        totals[category] = totals.get(category, 0) + amount
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(("category", "total"))
    for category in sorted(totals, key=lambda value: value.encode("utf-8")):
        writer.writerow((category, str(totals[category])))
    return stream.getvalue().encode("utf-8")


def build_csv_group_totals_fixture_bundle(
    task: ExecutableStaticTask,
    profile: ExecutableFixtureProfile,
) -> ExecutableFixtureBundle:
    task, profile = _validate_task_profile(task, profile)
    inputs = _fixture_inputs(profile, task.parameters)
    content = _derive_output(inputs, task.parameters)
    output = OracleOutputRecord(
        "output/totals.csv",
        content,
        OUTPUT_MODE,
    )
    definition = FixtureDefinition(
        fixture_id=f"dev.csv-group-totals.{profile.profile_id}",
        inputs=inputs,
        expected_files=(
            ExpectedFile(
                output.path,
                maximum_bytes=OUTPUT_LIMIT,
                mode=OUTPUT_MODE,
            ),
        ),
    )
    oracle = build_trusted_fixture_oracle(
        (output,),
        semantic_verifier_identity="verify-csv-group-totals-v1",
    )
    return build_executable_fixture_bundle(
        task_contract_sha256=task.task_contract_sha256,
        profile_sha256=profile.profile_sha256,
        definition=definition,
        oracle=oracle,
    )


__all__ = [
    "ExecutableFixtureCsvError",
    "build_csv_group_totals_fixture_bundle",
]
