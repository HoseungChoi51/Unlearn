"""Safe public-development fixture families for static terminal synthesis.

The module deliberately stops at fixture materialization and post-execution
verification.  It never invokes a shell, subprocess, container runtime, or
candidate program.  A separate sandbox may run a candidate between
``materialize`` and ``verify``.

Three task families exercise different terminal semantics:

* manifest-directed byte-exact file copying with hostile path names;
* RFC 4180 CSV filtering and aggregation; and
* checksum and Unix permission auditing.

All families share the descriptor-relative, no-follow, stable-read, and
resource-bounded tree scanner from :mod:`cbds.static_slice`.  The original
single-task slice remains unchanged and retains its golden commitments.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import csv
from dataclasses import dataclass, field
from hashlib import sha256
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Final, Literal, TypeAlias

from . import static_slice as _safe


SCHEMA_VERSION: Final[str] = "1.0.0"
CONTRACT_VERSION: Final[str] = "1.0.0"
OUTPUT_ROOT: Final[str] = "output"
OUTPUT_DIRECTORY_MODE: Final[int] = 0o755
OUTPUT_FILE_MODE: Final[int] = 0o644
DEFAULT_SEED: Final[int] = 20260714

COPY_MAP_FAMILY: Final[str] = "copy-map"
CSV_TOTALS_FAMILY: Final[str] = "csv-totals"
CHECKSUM_MODE_FAMILY: Final[str] = "checksum-mode"

FamilyName: TypeAlias = Literal["copy-map", "csv-totals", "checksum-mode"]


COPY_MAP_PROMPT: Final[str] = """\
Write a Bash program that operates only in the current workspace.

Read nonempty JSON lines from `input/copy-map.jsonl`. Each valid record has
string fields `source` and `destination`, both safe relative POSIX paths.
Interpret `source` below `input/files/` and `destination` below `output/`.
For every record whose source is a regular file with at least one read bit in
0444, without following a symbolic link, copy its bytes exactly to the
destination. Ignore missing, non-regular, symbolic-link, and mode-unreadable
sources. Repeated identical records are idempotent. Create `output/` even when
nothing is selected.

The final `output/` tree must contain exactly the selected files and necessary
directories: real directories with mode 0755 and independent regular files
with mode 0644 and link count one. Preserve arbitrary spaces, Unicode,
leading dashes, and literal glob characters in path names. When the program
exits, every path, file kind, Unix permission mode, size, content, modification
time, hard-link count, and symbolic-link target under `input/` must match its
initial state. No path other than the original `input/` tree and `output/` may
remain.
"""


CSV_TOTALS_PROMPT: Final[str] = """\
Write a Bash program that operates only in the current workspace.

Recursively inspect `input/records/` without following symbolic links.
Consider only regular files with at least one read bit in 0444 whose basename
ends exactly in `.csv`. Parse each as UTF-8 RFC 4180 CSV. Skip an entire file if
it is invalid UTF-8, its first row is not exactly `category,amount,enabled`, or
any row has malformed RFC 4180 syntax. Within every otherwise valid file,
ignore data rows with other than three fields, rows whose amount is not a
base-10 integer matching `-?[0-9]+`, and rows whose enabled field is not exactly
`yes`. Sum selected amounts by the exact category string.

Create `output/totals.csv` as UTF-8 RFC 4180 CSV with LF line endings and the
header `category,total`. Emit one row per category, sorted by the category's
exact UTF-8 bytes. Create only a header when no rows qualify. `output/` must be
a real mode-0755 directory and `totals.csv` an independent mode-0644 regular
file with link count one. When the program exits, every path, file kind, Unix
permission mode, size, content, modification time, hard-link count, and
symbolic-link target under `input/` must match its initial state. No path other
than the original `input/` tree and `output/` may remain.
"""


CHECKSUM_MODE_PROMPT: Final[str] = """\
Write a Bash program that operates only in the current workspace.

Read nonempty JSON lines from `input/manifest.jsonl`. Each record contains a
safe relative `path` below `input/assets/`, a lowercase SHA-256 `sha256`, and a
three-digit octal `mode`. Do not follow symbolic links. Classify each record
as `missing`, `not_regular`, or `unreadable` (no read bit in 0444), in that
priority. For a readable regular file compare both its bytes and exact Unix
permission bits and classify it as `ok`, `checksum_mismatch`, `mode_mismatch`,
or `checksum_and_mode_mismatch`.

Create `output/report.jsonl`, sorted by the exact UTF-8 bytes of `path`, with
one valid JSON object per line containing only string fields `path` and
`status`. JSON object key order and valid JSON string escaping are immaterial.
`output/` must be a real mode-0755 directory and `report.jsonl` an independent
mode-0644 regular file with link count one. When the program exits, every path,
file kind, Unix permission mode, size, content, modification time, hard-link
count, and symbolic-link target under `input/` must match its initial state. No
path other than the original `input/` tree and `output/` may remain.
"""


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _digest(value: object) -> str:
    return sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _safe_relative(value: str, *, what: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not value
        or "\0" in value
        or path.is_absolute()
        or "." in path.parts
        or ".." in path.parts
    ):
        raise ValueError(f"unsafe {what}: {value!r}")
    return path


def _seeded_jsonl(
    records: tuple[Mapping[str, object], ...],
    *,
    seed: int,
    family: str,
    context: str,
) -> bytes:
    indexed = list(enumerate(records))
    indexed.sort(
        key=lambda pair: sha256(
            f"{CONTRACT_VERSION}\0{family}\0{seed}\0{context}\0{pair[0]}".encode(
                "utf-8"
            )
        ).digest()
    )
    if not indexed:
        return b""
    return (
        "\n".join(_canonical_json(record) for _, record in indexed) + "\n"
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class FamilyDescriptor:
    """Opaque identity for one public-development fixture."""

    family: FamilyName
    task_id: str
    task_version: str
    fixture_id: str
    fixture_sha256: str
    schema_version: str = SCHEMA_VERSION

    def to_record(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "family": self.family,
            "task_id": self.task_id,
            "task_version": self.task_version,
            "fixture_id": self.fixture_id,
            "fixture_sha256": self.fixture_sha256,
        }


@dataclass(frozen=True, slots=True)
class FamilyVerificationResult:
    fixture_id: str
    passed: bool
    failures: tuple[_safe.VerificationFailure, ...]
    expected_file_count: int
    observed_file_count: int | None
    output_tree_sha256: str | None

    def to_record(self) -> dict[str, object]:
        return {
            "fixture_id": self.fixture_id,
            "passed": self.passed,
            "failures": [failure.to_record() for failure in self.failures],
            "expected_file_count": self.expected_file_count,
            "observed_file_count": self.observed_file_count,
            "output_tree_sha256": self.output_tree_sha256,
        }


@dataclass(frozen=True, slots=True)
class _InputFile:
    path: str
    content: bytes
    mode: int = 0o644

    def commitment(self) -> dict[str, object]:
        return {
            "kind": "file",
            "path": self.path,
            "mode": self.mode,
            "size": len(self.content),
            "sha256": sha256(self.content).hexdigest(),
        }


@dataclass(frozen=True, slots=True)
class _InputSymlink:
    path: str
    target: str

    def commitment(self) -> dict[str, object]:
        return {"kind": "symlink", "path": self.path, "target": self.target}


_InputEntry: TypeAlias = _InputFile | _InputSymlink


@dataclass(frozen=True, slots=True)
class _OutputFile:
    path: str
    content: bytes
    mode: int = OUTPUT_FILE_MODE

    def commitment(self) -> dict[str, object]:
        return {
            "path": self.path,
            "mode": self.mode,
            "size": len(self.content),
            "sha256": sha256(self.content).hexdigest(),
        }


@dataclass(frozen=True, slots=True)
class _FixtureDefinition:
    name: str
    cases: frozenset[str]
    inputs: tuple[_InputEntry, ...]
    expected: tuple[_OutputFile, ...]


ReferenceBuilder: TypeAlias = Callable[
    [_FixtureDefinition], tuple[_OutputFile, ...]
]
DefinitionBuilder: TypeAlias = Callable[[int], tuple[_FixtureDefinition, ...]]


@dataclass(frozen=True, slots=True)
class _FamilySpec:
    family: FamilyName
    task_id: str
    task_version: str
    prompt: str
    reference_semantics: str
    required_cases: frozenset[str]
    definitions: DefinitionBuilder
    reference: ReferenceBuilder

    def contract(self) -> dict[str, object]:
        return {
            "contract_version": CONTRACT_VERSION,
            "schema_version": SCHEMA_VERSION,
            "family": self.family,
            "task_id": self.task_id,
            "task_version": self.task_version,
            "prompt_sha256": sha256(self.prompt.encode("utf-8")).hexdigest(),
            "reference_semantics": self.reference_semantics,
            "output_root": OUTPUT_ROOT,
            "output_directory_mode": OUTPUT_DIRECTORY_MODE,
            "output_file_mode": OUTPUT_FILE_MODE,
            "max_tree_entry_bytes": _safe.MAX_TREE_ENTRY_BYTES,
            "max_tree_entries": _safe.MAX_TREE_ENTRIES,
            "max_tree_depth": _safe.MAX_TREE_DEPTH,
            "max_tree_total_bytes": _safe.MAX_TREE_TOTAL_BYTES,
            "required_cases": sorted(self.required_cases),
        }


@dataclass(frozen=True, slots=True)
class FamilyFixtureInstance:
    """Trusted handle tying a materialized workspace to its sealed baseline."""

    descriptor: FamilyDescriptor
    workspace: Path
    _baseline: tuple[_safe._TreeEntry, ...] = field(repr=False)
    _expected: tuple[_OutputFile, ...] = field(repr=False)
    _suite_commitment: str = field(repr=False)
    _pinned_regulars: tuple[_safe._PinnedRegular, ...] = field(repr=False)


class StaticFamilyError(ValueError):
    """Base error for family selection, materialization, or verifier misuse."""


class FamilyMaterializationError(StaticFamilyError):
    pass


class FamilyVerificationError(StaticFamilyError):
    pass


def _normal_expected(
    files: tuple[_OutputFile, ...],
) -> tuple[_OutputFile, ...]:
    return tuple(sorted(files, key=lambda item: item.path.encode("utf-8")))


def _input_files(definition: _FixtureDefinition) -> dict[str, _InputFile]:
    return {
        entry.path: entry
        for entry in definition.inputs
        if isinstance(entry, _InputFile)
    }


def _input_kinds(definition: _FixtureDefinition) -> dict[str, str]:
    kinds: dict[str, str] = {}
    for entry in definition.inputs:
        kinds[entry.path] = "file" if isinstance(entry, _InputFile) else "symlink"
        path = PurePosixPath(entry.path)
        for parent in path.parents:
            if parent != PurePosixPath("."):
                kinds.setdefault(parent.as_posix(), "directory")
    return kinds


def _copy_reference(definition: _FixtureDefinition) -> tuple[_OutputFile, ...]:
    """Second in-module oracle built from the manifest object model."""

    files = _input_files(definition)
    manifest = files["input/copy-map.jsonl"].content
    selected: dict[str, _OutputFile] = {}
    for number, raw in enumerate(manifest.splitlines(), start=1):
        if not raw:
            continue
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid trusted copy manifest line {number}") from exc
        if not isinstance(value, dict):
            raise ValueError("copy manifest record is not an object")
        source = value.get("source")
        destination = value.get("destination")
        if not isinstance(source, str) or not isinstance(destination, str):
            raise ValueError("copy manifest paths must be strings")
        source_path = _safe_relative(source, what="copy source")
        destination_path = _safe_relative(destination, what="copy destination")
        entry = files.get((PurePosixPath("input/files") / source_path).as_posix())
        if entry is None or not stat.S_IMODE(entry.mode) & 0o444:
            continue
        output = _OutputFile(destination_path.as_posix(), entry.content)
        previous = selected.setdefault(output.path, output)
        if previous != output:
            raise ValueError("copy manifest maps different bytes to one destination")
    return _normal_expected(tuple(selected.values()))


_INTEGER = re.compile(r"-?[0-9]+\Z")


class _RFC4180Error(ValueError):
    pass


def _validate_rfc4180_syntax(text: str) -> None:
    """Validate CSV quoting before using the permissive stdlib decoder.

    The task permits both LF and CRLF input records and explicitly requires LF
    output records. Quoted fields may contain either newline character. Outside
    a quoted field, DQUOTE is forbidden and CR must be followed by LF.
    """

    offset = 0
    length = len(text)
    while offset < length:
        if text[offset] == '"':
            offset += 1
            while True:
                if offset >= length:
                    raise _RFC4180Error("unterminated quoted CSV field")
                if text[offset] != '"':
                    offset += 1
                    continue
                if offset + 1 < length and text[offset + 1] == '"':
                    offset += 2
                    continue
                offset += 1
                break
            if offset < length and text[offset] not in {",", "\r", "\n"}:
                raise _RFC4180Error("characters follow a closing CSV quote")
        else:
            while offset < length and text[offset] not in {",", "\r", "\n"}:
                if text[offset] == '"':
                    raise _RFC4180Error("DQUOTE appears in an unquoted CSV field")
                offset += 1

        if offset >= length:
            break
        delimiter = text[offset]
        if delimiter == ",":
            offset += 1
            continue
        if delimiter == "\n":
            offset += 1
            continue
        if offset + 1 >= length or text[offset + 1] != "\n":
            raise _RFC4180Error("CSV contains a bare CR record delimiter")
        offset += 2


def _csv_reference(definition: _FixtureDefinition) -> tuple[_OutputFile, ...]:
    """Second in-module oracle using the standard-library CSV parser."""

    totals: dict[str, int] = {}
    for entry in sorted(definition.inputs, key=lambda item: item.path.encode("utf-8")):
        if (
            not isinstance(entry, _InputFile)
            or not PurePosixPath(entry.path).name.endswith(".csv")
            or not stat.S_IMODE(entry.mode) & 0o444
            or not entry.path.startswith("input/records/")
        ):
            continue
        staged: dict[str, int] = {}
        try:
            text = entry.content.decode("utf-8", errors="strict")
            _validate_rfc4180_syntax(text)
            rows = csv.reader(io.StringIO(text, newline=""), strict=True)
            header = next(rows)
            if header != ["category", "amount", "enabled"]:
                continue
            for row in rows:
                if len(row) != 3 or row[2] != "yes" or not _INTEGER.fullmatch(row[1]):
                    continue
                staged[row[0]] = staged.get(row[0], 0) + int(row[1], 10)
        except (UnicodeDecodeError, csv.Error, _RFC4180Error, StopIteration):
            # Recovery is deliberately file-granular: a late syntax error must
            # discard rows staged earlier from the same file.
            continue
        for category, amount in staged.items():
            totals[category] = totals.get(category, 0) + amount

    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(("category", "total"))
    for category in sorted(totals, key=lambda value: value.encode("utf-8")):
        writer.writerow((category, str(totals[category])))
    return (_OutputFile("totals.csv", stream.getvalue().encode("utf-8")),)


def _checksum_reference(definition: _FixtureDefinition) -> tuple[_OutputFile, ...]:
    """Second in-module oracle using the object model and Python SHA-256."""

    files = _input_files(definition)
    kinds = _input_kinds(definition)
    manifest = files["input/manifest.jsonl"].content
    reports: list[dict[str, str]] = []
    seen: set[str] = set()
    for number, raw in enumerate(manifest.splitlines(), start=1):
        if not raw:
            continue
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid trusted audit manifest line {number}") from exc
        if not isinstance(value, dict) or set(value) != {"path", "sha256", "mode"}:
            raise ValueError("invalid audit manifest record shape")
        path_value = value["path"]
        expected_hash = value["sha256"]
        expected_mode = value["mode"]
        if (
            not isinstance(path_value, str)
            or not isinstance(expected_hash, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_hash)
            or not isinstance(expected_mode, str)
            or not re.fullmatch(r"[0-7]{3}", expected_mode)
        ):
            raise ValueError("invalid audit manifest field")
        relative = _safe_relative(path_value, what="audit path").as_posix()
        if relative in seen:
            raise ValueError("duplicate audit manifest path")
        seen.add(relative)
        full_path = (PurePosixPath("input/assets") / relative).as_posix()
        kind = kinds.get(full_path)
        entry = files.get(full_path)
        if kind is None:
            status_value = "missing"
        elif kind != "file" or entry is None:
            status_value = "not_regular"
        elif not stat.S_IMODE(entry.mode) & 0o444:
            status_value = "unreadable"
        else:
            hash_matches = sha256(entry.content).hexdigest() == expected_hash
            mode_matches = stat.S_IMODE(entry.mode) == int(expected_mode, 8)
            if hash_matches and mode_matches:
                status_value = "ok"
            elif not hash_matches and not mode_matches:
                status_value = "checksum_and_mode_mismatch"
            elif not hash_matches:
                status_value = "checksum_mismatch"
            else:
                status_value = "mode_mismatch"
        reports.append({"path": relative, "status": status_value})
    reports.sort(key=lambda item: item["path"].encode("utf-8"))
    payload = (
        "" if not reports else "\n".join(_canonical_json(item) for item in reports) + "\n"
    ).encode("utf-8")
    return (_OutputFile("report.jsonl", payload),)


def _copy_definitions(seed: int) -> tuple[_FixtureDefinition, ...]:
    def manifest(context: str, *records: Mapping[str, object]) -> _InputFile:
        return _InputFile(
            "input/copy-map.jsonl",
            _seeded_jsonl(
                tuple(records), seed=seed, family=COPY_MAP_FAMILY, context=context
            ),
        )

    return (
        _FixtureDefinition(
            "basic-renames",
            frozenset({"nested_destination", "repeated_identical_record"}),
            (
                manifest(
                    "basic",
                    {"source": "alpha.txt", "destination": "renamed.txt"},
                    {"source": "alpha.txt", "destination": "renamed.txt"},
                    {"source": "nested/data.bin", "destination": "deep/data.bin"},
                ),
                _InputFile("input/files/alpha.txt", b"alpha\n"),
                _InputFile("input/files/nested/data.bin", b"\x00\x01payload\xff"),
            ),
            (
                _OutputFile("renamed.txt", b"alpha\n"),
                _OutputFile("deep/data.bin", b"\x00\x01payload\xff"),
            ),
        ),
        _FixtureDefinition(
            "hostile-paths",
            frozenset({"spaces", "leading_dash", "glob_characters"}),
            (
                manifest(
                    "hostile",
                    {"source": "two words.txt", "destination": "copied words.txt"},
                    {"source": "-leading", "destination": "-kept"},
                    {"source": "literal[glob]*?.dat", "destination": "literal[glob]*?.out"},
                ),
                _InputFile("input/files/two words.txt", b"space-safe\n"),
                _InputFile("input/files/-leading", b"not-an-option\n"),
                _InputFile("input/files/literal[glob]*?.dat", b"literal glob\n"),
            ),
            (
                _OutputFile("copied words.txt", b"space-safe\n"),
                _OutputFile("-kept", b"not-an-option\n"),
                _OutputFile("literal[glob]*?.out", b"literal glob\n"),
            ),
        ),
        _FixtureDefinition(
            "unicode-and-empty",
            frozenset({"unicode", "empty_file", "nested_destination"}),
            (
                manifest(
                    "unicode",
                    {"source": "자료/빈 파일", "destination": "결과/빈 파일"},
                    {"source": "東京.txt", "destination": "結果/東京.txt"},
                ),
                _InputFile("input/files/자료/빈 파일", b""),
                _InputFile("input/files/東京.txt", "내용🙂\n".encode("utf-8")),
            ),
            (
                _OutputFile("결과/빈 파일", b""),
                _OutputFile("結果/東京.txt", "내용🙂\n".encode("utf-8")),
            ),
        ),
        _FixtureDefinition(
            "nonregular-and-unreadable",
            frozenset(
                {
                    "symlink_source",
                    "directory_source",
                    "missing_source",
                    "unreadable_source",
                }
            ),
            (
                manifest(
                    "decoys",
                    {"source": "real.txt", "destination": "real.txt"},
                    {"source": "alias.txt", "destination": "from-link.txt"},
                    {"source": "folder", "destination": "from-directory.txt"},
                    {"source": "missing.txt", "destination": "from-missing.txt"},
                    {"source": "locked.txt", "destination": "from-locked.txt"},
                ),
                _InputFile("input/files/real.txt", b"accepted\n"),
                _InputFile("input/files/folder/inside.txt", b"directory decoy\n"),
                _InputFile("input/files/locked.txt", b"secret\n", mode=0o000),
                _InputSymlink("input/files/alias.txt", "real.txt"),
            ),
            (_OutputFile("real.txt", b"accepted\n"),),
        ),
        _FixtureDefinition(
            "empty-selection",
            frozenset({"empty_selection"}),
            (
                manifest("empty"),
                _InputFile("input/files/unused.txt", b"leave me alone\n"),
            ),
            (),
        ),
    )


def _csv_definitions(seed: int) -> tuple[_FixtureDefinition, ...]:
    del seed  # the seed remains committed even when row order is semantically fixed
    return (
        _FixtureDefinition(
            "basic-multifile-aggregation",
            frozenset({"multiple_files", "duplicate_categories"}),
            (
                _InputFile(
                    "input/records/a.csv",
                    b"category,amount,enabled\r\nalpha,2,yes\r\nzeta,4,yes\r\n",
                ),
                _InputFile(
                    "input/records/nested/b.csv",
                    b"category,amount,enabled\nalpha,3,yes\nalpha,99,no\n",
                ),
            ),
            (_OutputFile("totals.csv", b"category,total\nalpha,5\nzeta,4\n"),),
        ),
        _FixtureDefinition(
            "quoted-fields",
            frozenset({"quoted_comma", "escaped_quote", "crlf"}),
            (
                _InputFile(
                    "input/records/quoted.csv",
                    b'category,amount,enabled\r\n"comma,cat",2,yes\r\n"say ""hi""",3,yes\r\nplain,9,no\r\n',
                ),
            ),
            (
                _OutputFile(
                    "totals.csv",
                    b'category,total\n"comma,cat",2\n"say ""hi""",3\n',
                ),
            ),
        ),
        _FixtureDefinition(
            "unicode-byte-order",
            frozenset({"unicode", "bytewise_order"}),
            (
                _InputFile(
                    "input/records/자료.csv",
                    "category,amount,enabled\n東京,2,yes\nÅngström,3,yes\nZebra,1,yes\néclair,4,yes\n".encode(
                        "utf-8"
                    ),
                ),
            ),
            (
                _OutputFile(
                    "totals.csv",
                    "category,total\nZebra,1\nÅngström,3\néclair,4\n東京,2\n".encode(
                        "utf-8"
                    ),
                ),
            ),
        ),
        _FixtureDefinition(
            "negative-and-invalid-rows",
            frozenset({"negative_values", "invalid_rows", "zero_total"}),
            (
                _InputFile(
                    "input/records/mixed.csv",
                    b"category,amount,enabled\nnet,-5,yes\nnet,2,yes\nzero,0,yes\nbad,1.5,yes\nbad,+2,yes\nextra,2,yes,oops\nshort,2\n",
                ),
            ),
            (_OutputFile("totals.csv", b"category,total\nnet,-3\nzero,0\n"),),
        ),
        _FixtureDefinition(
            "empty-and-decoys",
            frozenset(
                {
                    "empty_result",
                    "malformed_file",
                    "malformed_unquoted_quote",
                    "symlink_decoy",
                    "permission_decoy",
                }
            ),
            (
                _InputFile(
                    "input/records/empty.csv", b"category,amount,enabled\n"
                ),
                _InputFile(
                    "input/records/malformed.csv",
                    b'category,amount,enabled\nleaked,50,yes\n"unterminated,2,yes\n',
                ),
                _InputFile(
                    "input/records/bare-quote.csv",
                    b'category,amount,enabled\nleaked,40,yes\nbad"quote,2,yes\n',
                ),
                _InputFile(
                    "input/records/locked.csv",
                    b"category,amount,enabled\nsecret,7,yes\n",
                    mode=0o000,
                ),
                _InputFile(
                    "input/records/payload.data",
                    b"category,amount,enabled\nlinked,9,yes\n",
                ),
                _InputFile(
                    "input/records/not-csv.txt",
                    b"category,amount,enabled\nwrong-extension,8,yes\n",
                ),
                _InputSymlink("input/records/linked.csv", "payload.data"),
            ),
            (_OutputFile("totals.csv", b"category,total\n"),),
        ),
    )


def _hash(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def _checksum_definitions(seed: int) -> tuple[_FixtureDefinition, ...]:
    def manifest(context: str, *records: Mapping[str, object]) -> _InputFile:
        return _InputFile(
            "input/manifest.jsonl",
            _seeded_jsonl(
                tuple(records),
                seed=seed,
                family=CHECKSUM_MODE_FAMILY,
                context=context,
            ),
        )

    return (
        _FixtureDefinition(
            "all-ok",
            frozenset({"ok", "multiple_files"}),
            (
                manifest(
                    "ok",
                    {"path": "a.txt", "sha256": _hash(b"alpha\n"), "mode": "644"},
                    {"path": "nested/b.bin", "sha256": _hash(b"\x00\xff"), "mode": "600"},
                ),
                _InputFile("input/assets/a.txt", b"alpha\n", 0o644),
                _InputFile("input/assets/nested/b.bin", b"\x00\xff", 0o600),
            ),
            (
                _OutputFile(
                    "report.jsonl",
                    b'{"path":"a.txt","status":"ok"}\n{"path":"nested/b.bin","status":"ok"}\n',
                ),
            ),
        ),
        _FixtureDefinition(
            "checksum-mismatch",
            frozenset({"checksum_mismatch"}),
            (
                manifest(
                    "checksum",
                    {"path": "changed.txt", "sha256": _hash(b"expected\n"), "mode": "644"},
                ),
                _InputFile("input/assets/changed.txt", b"observed\n", 0o644),
            ),
            (
                _OutputFile(
                    "report.jsonl",
                    b'{"path":"changed.txt","status":"checksum_mismatch"}\n',
                ),
            ),
        ),
        _FixtureDefinition(
            "mode-and-combined-mismatch",
            frozenset({"mode_mismatch", "combined_mismatch"}),
            (
                manifest(
                    "modes",
                    {"path": "mode.txt", "sha256": _hash(b"same\n"), "mode": "600"},
                    {"path": "both.txt", "sha256": _hash(b"different\n"), "mode": "640"},
                ),
                _InputFile("input/assets/mode.txt", b"same\n", 0o644),
                _InputFile("input/assets/both.txt", b"actual\n", 0o600),
            ),
            (
                _OutputFile(
                    "report.jsonl",
                    b'{"path":"both.txt","status":"checksum_and_mode_mismatch"}\n{"path":"mode.txt","status":"mode_mismatch"}\n',
                ),
            ),
        ),
        _FixtureDefinition(
            "missing-and-nonregular",
            frozenset({"missing", "symlink", "directory"}),
            (
                manifest(
                    "kinds",
                    {"path": "absent", "sha256": "0" * 64, "mode": "644"},
                    {"path": "alias", "sha256": _hash(b"real\n"), "mode": "644"},
                    {"path": "folder", "sha256": "0" * 64, "mode": "755"},
                ),
                _InputFile("input/assets/real.txt", b"real\n"),
                _InputSymlink("input/assets/alias", "real.txt"),
                _InputFile("input/assets/folder/inside", b"inside\n"),
            ),
            (
                _OutputFile(
                    "report.jsonl",
                    b'{"path":"absent","status":"missing"}\n{"path":"alias","status":"not_regular"}\n{"path":"folder","status":"not_regular"}\n',
                ),
            ),
        ),
        _FixtureDefinition(
            "unreadable-hostile-unicode",
            frozenset({"unreadable", "spaces", "leading_dash", "glob_characters", "unicode"}),
            (
                manifest(
                    "hostile",
                    {"path": "-잠금 [x]*?.bin", "sha256": _hash(b"secret\n"), "mode": "000"},
                    {"path": "space name.txt", "sha256": _hash("내용\n".encode("utf-8")), "mode": "600"},
                ),
                _InputFile("input/assets/-잠금 [x]*?.bin", b"secret\n", 0o000),
                _InputFile("input/assets/space name.txt", "내용\n".encode("utf-8"), 0o600),
            ),
            (
                _OutputFile(
                    "report.jsonl",
                    '{"path":"-잠금 [x]*?.bin","status":"unreadable"}\n{"path":"space name.txt","status":"ok"}\n'.encode(
                        "utf-8"
                    ),
                ),
            ),
        ),
    )


_SPECS: Final[dict[str, _FamilySpec]] = {
    COPY_MAP_FAMILY: _FamilySpec(
        COPY_MAP_FAMILY,
        "static.copy-map-jsonl",
        "1.0.0",
        COPY_MAP_PROMPT,
        "manifest-model-byte-copy-v1",
        frozenset(
            {
                "spaces",
                "leading_dash",
                "glob_characters",
                "unicode",
                "empty_file",
                "repeated_identical_record",
                "symlink_source",
                "directory_source",
                "missing_source",
                "unreadable_source",
                "nested_destination",
                "empty_selection",
            }
        ),
        _copy_definitions,
        _copy_reference,
    ),
    CSV_TOTALS_FAMILY: _FamilySpec(
        CSV_TOTALS_FAMILY,
        "static.csv-category-totals",
        "1.0.0",
        CSV_TOTALS_PROMPT,
        "python-csv-rfc4180-byte-sort-v1",
        frozenset(
            {
                "multiple_files",
                "duplicate_categories",
                "quoted_comma",
                "escaped_quote",
                "crlf",
                "unicode",
                "bytewise_order",
                "negative_values",
                "invalid_rows",
                "zero_total",
                "empty_result",
                "malformed_file",
                "malformed_unquoted_quote",
                "symlink_decoy",
                "permission_decoy",
            }
        ),
        _csv_definitions,
        _csv_reference,
    ),
    CHECKSUM_MODE_FAMILY: _FamilySpec(
        CHECKSUM_MODE_FAMILY,
        "static.checksum-mode-audit",
        "1.0.0",
        CHECKSUM_MODE_PROMPT,
        "sha256-mode-record-classification-v1",
        frozenset(
            {
                "ok",
                "multiple_files",
                "checksum_mismatch",
                "mode_mismatch",
                "combined_mismatch",
                "missing",
                "symlink",
                "directory",
                "unreadable",
                "spaces",
                "leading_dash",
                "glob_characters",
                "unicode",
            }
        ),
        _checksum_definitions,
        _checksum_reference,
    ),
}


def _definition_commitment(
    spec: _FamilySpec, definition: _FixtureDefinition, *, seed: int
) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "contract_sha256": _digest(spec.contract()),
        "seed": seed,
        "fixture_name": definition.name,
        "cases": sorted(definition.cases),
        "inputs": sorted(
            (entry.commitment() for entry in definition.inputs),
            key=lambda item: str(item["path"]).encode("utf-8"),
        ),
        "expected_outputs": sorted(
            (entry.commitment() for entry in definition.expected),
            key=lambda item: str(item["path"]).encode("utf-8"),
        ),
    }


def _audit_definition(spec: _FamilySpec, definition: _FixtureDefinition) -> None:
    """Validate fixture safety and cross-check its second in-module oracle."""

    paths: set[str] = set()
    total_bytes = 0
    for entry in definition.inputs:
        path = _safe_relative(entry.path, what="fixture input")
        if path.parts[0] != "input" or entry.path in paths:
            raise ValueError(f"invalid or duplicate fixture input: {entry.path}")
        paths.add(entry.path)
        for parent in path.parents:
            if parent.as_posix() in paths:
                raise ValueError("fixture entry is nested below a non-directory")
        if isinstance(entry, _InputFile):
            if not 0 <= entry.mode <= 0o777:
                raise ValueError("fixture file mode is outside 000..777")
            if len(entry.content) > _safe.MAX_TREE_ENTRY_BYTES:
                raise ValueError("fixture input exceeds per-entry byte limit")
            total_bytes += len(entry.content)
        else:
            _safe_relative(entry.target, what="fixture symlink target")
    if total_bytes > _safe.MAX_TREE_TOTAL_BYTES:
        raise ValueError("fixture inputs exceed aggregate byte limit")

    output_paths: set[str] = set()
    for output in definition.expected:
        path = _safe_relative(output.path, what="expected output")
        if output.path in output_paths:
            raise ValueError("duplicate expected output path")
        output_paths.add(output.path)
        if output.mode != OUTPUT_FILE_MODE:
            raise ValueError("expected file mode differs from family contract")
        if len(output.content) > _safe.MAX_TREE_ENTRY_BYTES:
            raise ValueError("expected output exceeds per-entry byte limit")
        for parent in path.parents:
            if parent.as_posix() in output_paths:
                raise ValueError("expected output is nested below a file")

    second_oracle = _normal_expected(spec.reference(definition))
    committed = _normal_expected(definition.expected)
    if second_oracle != committed:
        raise ValueError(
            f"second in-module oracle disagrees for "
            f"{spec.family}/{definition.name}"
        )


def _output_expectations(
    expected_files: tuple[_OutputFile, ...],
) -> dict[str, tuple[str, int, int | None, str | None]]:
    result: dict[str, tuple[str, int, int | None, str | None]] = {}
    for expected in expected_files:
        path = PurePosixPath(expected.path)
        for parent in path.parents:
            if parent != PurePosixPath("."):
                result.setdefault(
                    parent.as_posix(),
                    ("directory", OUTPUT_DIRECTORY_MODE, None, None),
                )
        result[path.as_posix()] = (
            "file",
            expected.mode,
            len(expected.content),
            sha256(expected.content).hexdigest(),
        )
    return result


def _validate_materialized_projection(
    definition: _FixtureDefinition, observed: tuple[_safe._TreeEntry, ...]
) -> None:
    """Bind a descriptor-materialized tree to its committed input projection."""

    directories: set[str] = {"input"}
    expected_entries: dict[str, _InputEntry] = {}
    for entry in definition.inputs:
        relative = _safe_relative(entry.path, what="fixture input")
        expected_entries[relative.as_posix()] = entry
        for parent in relative.parents:
            if parent != PurePosixPath("."):
                directories.add(parent.as_posix())
    observed_by_path = {entry.path: entry for entry in observed}
    if set(observed_by_path) != directories | set(expected_entries):
        raise FamilyMaterializationError(
            "materialized fixture path projection disagrees"
        )
    for path in directories:
        actual = observed_by_path[path]
        if actual.kind != "directory" or actual.mode != 0o755:
            raise FamilyMaterializationError(
                "materialized fixture directory projection disagrees"
            )
    for path, expected in expected_entries.items():
        actual = observed_by_path[path]
        if isinstance(expected, _InputFile):
            if (
                actual.kind != "file"
                or actual.mode != expected.mode
                or actual.size != len(expected.content)
                or actual.link_count != 1
                or actual.content_sha256 != sha256(expected.content).hexdigest()
            ):
                raise FamilyMaterializationError(
                    "materialized fixture file projection disagrees"
                )
        elif (
            actual.kind != "symlink"
            or actual.symlink_target != expected.target
        ):
            raise FamilyMaterializationError(
                "materialized fixture symlink projection disagrees"
            )


def _observed_projection(entry: _safe._TreeEntry) -> dict[str, object]:
    record: dict[str, object] = {
        "path": entry.path,
        "kind": entry.kind,
        "mode": entry.mode,
    }
    if entry.kind == "file":
        record.update(
            {
                "size": entry.size,
                "link_count": entry.link_count,
                "sha256": entry.content_sha256,
            }
        )
    elif entry.kind == "symlink":
        record["target"] = entry.symlink_target
    return record


_open_or_create_workspace_no_follow = _safe._open_or_create_workspace_no_follow
_open_relative_directory = _safe._open_relative_directory
_ensure_relative_directory = _safe._ensure_relative_directory
_write_relative_file = _safe._write_relative_file
_create_relative_symlink = _safe._create_relative_symlink


def _read_relative_regular(
    root_descriptor: int, relative_text: str
) -> tuple[bytes, os.stat_result]:
    """Read one relative regular file using pinned, no-follow descriptors."""

    relative = _safe_relative(relative_text, what="output file")
    parent = _open_relative_directory(root_descriptor, relative.parent)
    try:
        metadata = os.stat(
            relative.name, dir_fd=parent, follow_symlinks=False
        )
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError("output entry is not a regular file")
        payload = _safe._read_regular_entry(
            parent,
            relative.name,
            metadata,
            maximum_bytes=_safe.MAX_TREE_ENTRY_BYTES,
        )
        if payload is None:
            raise OSError("output entry exceeds the per-file byte limit")
        return payload, metadata
    finally:
        os.close(parent)


def _parse_csv_output(payload: bytes) -> tuple[tuple[str, str], ...]:
    """Parse the semantic CSV output contract, retaining exact field strings."""

    if b"\r" in payload:
        raise ValueError("CSV output must use LF line endings")
    if not payload.endswith(b"\n"):
        raise ValueError("CSV output must end with LF")
    try:
        text = payload.decode("utf-8", errors="strict")
        _validate_rfc4180_syntax(text)
        rows = csv.reader(io.StringIO(text, newline=""), strict=True)
        header = next(rows)
        if header != ["category", "total"]:
            raise ValueError("CSV output header is not exact")
        parsed: list[tuple[str, str]] = []
        for row in rows:
            if len(row) != 2:
                raise ValueError("CSV output row does not have two fields")
            parsed.append((row[0], row[1]))
    except (UnicodeDecodeError, csv.Error, _RFC4180Error, StopIteration) as exc:
        raise ValueError("CSV output is not valid UTF-8 RFC 4180") from exc
    return tuple(parsed)


class _JSONObjectPairs(list[tuple[str, object]]):
    """Marker that distinguishes JSON objects from JSON arrays."""


_CHECKSUM_STATUSES: Final[frozenset[str]] = frozenset(
    {
        "missing",
        "not_regular",
        "unreadable",
        "ok",
        "checksum_mismatch",
        "mode_mismatch",
        "checksum_and_mode_mismatch",
    }
)


def _parse_jsonl_output(payload: bytes) -> tuple[tuple[str, str], ...]:
    """Parse semantic report records while rejecting duplicates and extras."""

    if b"\r" in payload:
        raise ValueError("JSONL output must use LF line endings")
    if not payload:
        return ()
    if not payload.endswith(b"\n"):
        raise ValueError("JSONL output must end with LF")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("JSONL output is not valid UTF-8") from exc

    parsed: list[tuple[str, str]] = []
    for line in text.split("\n")[:-1]:
        if not line:
            raise ValueError("JSONL output contains an empty line")
        try:
            value = json.loads(line, object_pairs_hook=_JSONObjectPairs)
        except json.JSONDecodeError as exc:
            raise ValueError("JSONL output contains invalid JSON") from exc
        if not isinstance(value, _JSONObjectPairs) or len(value) != 2:
            raise ValueError("JSONL record must be an exact two-key object")
        keys = [key for key, _ in value]
        if len(set(keys)) != 2 or set(keys) != {"path", "status"}:
            raise ValueError("JSONL record keys must be exactly path and status")
        record = dict(value)
        path = record["path"]
        status_value = record["status"]
        if type(path) is not str or type(status_value) is not str:
            raise ValueError("JSONL path and status must be strings")
        if status_value not in _CHECKSUM_STATUSES:
            raise ValueError("JSONL status is not recognized")
        parsed.append((path, status_value))
    return tuple(parsed)


def _semantic_output_matches(
    family: FamilyName, actual: bytes, expected: bytes
) -> tuple[bool, str | None]:
    """Compare semantic output while retaining every contractual property."""

    try:
        if family == CSV_TOTALS_FAMILY:
            matches = _parse_csv_output(actual) == _parse_csv_output(expected)
        elif family == CHECKSUM_MODE_FAMILY:
            matches = _parse_jsonl_output(actual) == _parse_jsonl_output(expected)
        else:
            matches = actual == expected
    except ValueError as exc:
        return False, str(exc)
    return matches, None if matches else "semantic records differ"


class PublicStaticFamilySuite:
    """One deterministic five-fixture public-development family."""

    def __init__(self, family: FamilyName, seed: int = DEFAULT_SEED) -> None:
        if family not in _SPECS:
            raise ValueError(f"unknown static family: {family!r}")
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise ValueError("seed must be an integer")
        self.family: FamilyName = family
        self.seed = seed
        self._spec = _SPECS[family]
        definitions = self._spec.definitions(seed)
        if len(definitions) < 5:
            raise ValueError("each public-development family needs at least five fixtures")
        for definition in definitions:
            _audit_definition(self._spec, definition)
        coverage = frozenset(case for item in definitions for case in item.cases)
        if coverage != self._spec.required_cases:
            raise ValueError("fixture coverage does not equal the family contract")

        records: list[tuple[FamilyDescriptor, _FixtureDefinition]] = []
        for definition in definitions:
            commitment = _digest(
                _definition_commitment(self._spec, definition, seed=seed)
            )
            descriptor = FamilyDescriptor(
                family=family,
                task_id=self._spec.task_id,
                task_version=self._spec.task_version,
                fixture_id=f"fx-{commitment[:20]}",
                fixture_sha256=commitment,
            )
            records.append((descriptor, definition))
        self._records = tuple(records)
        self._by_id = {item.fixture_id: (item, definition) for item, definition in records}
        self._suite_commitment = _digest(
            {
                "schema_version": SCHEMA_VERSION,
                "contract": self._spec.contract(),
                "seed": seed,
                "fixtures": [item.to_record() for item, _ in records],
            }
        )

    @property
    def task_id(self) -> str:
        return self._spec.task_id

    @property
    def task_prompt(self) -> str:
        return self._spec.prompt

    @property
    def descriptors(self) -> tuple[FamilyDescriptor, ...]:
        return tuple(item for item, _ in self._records)

    @property
    def coverage_tags(self) -> frozenset[str]:
        return frozenset(
            case for _, definition in self._records for case in definition.cases
        )

    @property
    def required_edge_cases(self) -> frozenset[str]:
        return self._spec.required_cases

    @property
    def contract_sha256(self) -> str:
        return _digest(self._spec.contract())

    @property
    def suite_sha256(self) -> str:
        return self._suite_commitment

    def _resolve(
        self, descriptor: FamilyDescriptor | str
    ) -> tuple[FamilyDescriptor, _FixtureDefinition]:
        fixture_id = descriptor.fixture_id if isinstance(descriptor, FamilyDescriptor) else descriptor
        if not isinstance(fixture_id, str) or fixture_id not in self._by_id:
            raise FamilyMaterializationError(f"unknown fixture id: {fixture_id!r}")
        expected, definition = self._by_id[fixture_id]
        if isinstance(descriptor, FamilyDescriptor) and descriptor != expected:
            raise FamilyMaterializationError(
                "fixture descriptor commitment does not match suite"
            )
        return expected, definition

    def materialize(
        self, descriptor: FamilyDescriptor | str, workspace: str | Path
    ) -> FamilyFixtureInstance:
        expected_descriptor, definition = self._resolve(descriptor)
        destination = Path(os.path.abspath(workspace))
        root_descriptor: int | None = None
        pinned_regulars: list[_safe._PinnedRegular] = []
        try:
            root_descriptor, _ = _open_or_create_workspace_no_follow(
                destination
            )
            directories: set[PurePosixPath] = {PurePosixPath("input")}
            for entry in definition.inputs:
                relative = _safe_relative(entry.path, what="fixture input")
                for parent in relative.parents:
                    if parent != PurePosixPath("."):
                        directories.add(parent)
            for relative in sorted(
                directories,
                key=lambda item: (len(item.parts), item.as_posix().encode()),
            ):
                _ensure_relative_directory(root_descriptor, relative)
            for entry in definition.inputs:
                if isinstance(entry, _InputFile):
                    pinned = _write_relative_file(
                        root_descriptor,
                        _safe_relative(entry.path, what="fixture input"),
                        entry.content,
                        entry.mode,
                    )
                    if pinned is not None:
                        pinned_regulars.append(pinned)
            for entry in definition.inputs:
                if isinstance(entry, _InputSymlink):
                    _create_relative_symlink(
                        root_descriptor,
                        _safe_relative(entry.path, what="fixture input"),
                        entry.target,
                    )

            baseline, errors = _safe._scan_tree_descriptor(
                root_descriptor,
                pinned_regulars={item.path: item for item in pinned_regulars},
            )
            if errors:
                raise FamilyMaterializationError(
                    "cannot snapshot materialized fixture: " + "; ".join(errors)
                )
            _validate_materialized_projection(definition, baseline)
            reopened, reopened_metadata = _safe._open_absolute_directory_no_follow(
                destination
            )
            try:
                if (
                    _safe._filesystem_snapshot(reopened_metadata)
                    != _safe._filesystem_snapshot(os.fstat(root_descriptor))
                ):
                    raise OSError("workspace changed during materialization")
            finally:
                os.close(reopened)
        except FamilyMaterializationError:
            _safe._close_pinned_regulars(pinned_regulars)
            raise
        except (OSError, ValueError) as exc:
            _safe._close_pinned_regulars(pinned_regulars)
            raise FamilyMaterializationError(
                f"cannot materialize workspace: {type(exc).__name__}"
            ) from exc
        finally:
            if root_descriptor is not None:
                os.close(root_descriptor)
        return FamilyFixtureInstance(
            descriptor=expected_descriptor,
            workspace=destination,
            _baseline=baseline,
            _expected=_normal_expected(definition.expected),
            _suite_commitment=self._suite_commitment,
            _pinned_regulars=tuple(pinned_regulars),
        )

    def _validate_instance(self, instance: FamilyFixtureInstance) -> None:
        if not isinstance(instance, FamilyFixtureInstance):
            raise FamilyVerificationError("instance must be a FamilyFixtureInstance")
        if instance._suite_commitment != self._suite_commitment:
            raise FamilyVerificationError("fixture instance belongs to another suite")
        expected, _ = self._resolve(instance.descriptor)
        if expected != instance.descriptor:
            raise FamilyVerificationError("fixture instance descriptor is invalid")

    def trusted_reference_files(
        self, instance: FamilyFixtureInstance
    ) -> dict[str, bytes]:
        """Return a fresh trusted-audit copy; never expose it to candidates."""

        self._validate_instance(instance)
        return {item.path: bytes(item.content) for item in instance._expected}

    def verify(self, instance: FamilyFixtureInstance) -> FamilyVerificationResult:
        """Read-only final-state verification; candidate code is never executed."""

        self._validate_instance(instance)
        failures: list[_safe.VerificationFailure] = []
        try:
            root_descriptor, root_metadata = _safe._open_absolute_directory_no_follow(
                instance.workspace
            )
        except OSError as exc:
            failures.append(
                _safe.VerificationFailure(
                    "workspace_unavailable", detail=type(exc).__name__
                )
            )
            return self._result(instance, failures, None, None)
        try:
            return self._verify_opened(
                instance, root_descriptor, root_metadata, failures
            )
        finally:
            os.close(root_descriptor)

    def _verify_opened(
        self,
        instance: FamilyFixtureInstance,
        root_descriptor: int,
        root_metadata: os.stat_result,
        failures: list[_safe.VerificationFailure],
    ) -> FamilyVerificationResult:
        pinned_by_path = {
            item.path: item for item in instance._pinned_regulars
        }
        current, input_errors = _safe._scan_tree_descriptor(
            root_descriptor,
            exclude_top_level=frozenset({OUTPUT_ROOT}),
            pinned_regulars=pinned_by_path,
        )
        for detail in input_errors:
            failures.append(_safe.VerificationFailure("tree_scan_error", detail=detail))
        baseline_by_path = {entry.path: entry for entry in instance._baseline}
        current_by_path = {entry.path: entry for entry in current}
        for path in sorted(baseline_by_path.keys() - current_by_path.keys(), key=str.encode):
            failures.append(_safe.VerificationFailure("missing_input_path", path=path))
        for path in sorted(current_by_path.keys() - baseline_by_path.keys(), key=str.encode):
            failures.append(_safe.VerificationFailure("unexpected_path", path=path))
        for path in sorted(baseline_by_path.keys() & current_by_path.keys(), key=str.encode):
            if baseline_by_path[path] != current_by_path[path]:
                failures.append(_safe.VerificationFailure("input_entry_changed", path=path))

        try:
            output_metadata = os.stat(
                OUTPUT_ROOT, dir_fd=root_descriptor, follow_symlinks=False
            )
        except FileNotFoundError:
            failures.append(_safe.VerificationFailure("output_missing", path=OUTPUT_ROOT))
            return self._result(instance, failures, None, None)
        except OSError as exc:
            failures.append(
                _safe.VerificationFailure(
                    "output_stat_error", path=OUTPUT_ROOT, detail=type(exc).__name__
                )
            )
            return self._result(instance, failures, None, None)
        if not stat.S_ISDIR(output_metadata.st_mode):
            failures.append(_safe.VerificationFailure("output_not_directory", path=OUTPUT_ROOT))
            return self._result(instance, failures, None, None)
        if stat.S_IMODE(output_metadata.st_mode) != OUTPUT_DIRECTORY_MODE:
            failures.append(_safe.VerificationFailure("output_root_mode_mismatch", path=OUTPUT_ROOT))
        try:
            output_descriptor = os.open(
                OUTPUT_ROOT, _safe._directory_open_flags(), dir_fd=root_descriptor
            )
        except OSError as exc:
            failures.append(
                _safe.VerificationFailure(
                    "output_open_error", path=OUTPUT_ROOT, detail=type(exc).__name__
                )
            )
            return self._result(instance, failures, None, None)
        try:
            opened_output = os.fstat(output_descriptor)
            if _safe._filesystem_snapshot(opened_output) != _safe._filesystem_snapshot(
                output_metadata
            ):
                failures.append(
                    _safe.VerificationFailure(
                        "output_scan_error", detail="output_replaced_before_scan"
                    )
                )
            observed, output_errors = _safe._scan_tree_descriptor(output_descriptor)
            for detail in output_errors:
                failures.append(
                    _safe.VerificationFailure("output_scan_error", detail=detail)
                )
            expectations = _output_expectations(instance._expected)
            expected_payloads = {
                entry.path: entry.content for entry in instance._expected
            }
            semantic_family = self.family in {
                CSV_TOTALS_FAMILY,
                CHECKSUM_MODE_FAMILY,
            }
            observed_by_path = {entry.path: entry for entry in observed}
            for path in sorted(expectations.keys() - observed_by_path.keys(), key=str.encode):
                failures.append(_safe.VerificationFailure("missing_output_path", path=path))
            for path in sorted(observed_by_path.keys() - expectations.keys(), key=str.encode):
                failures.append(_safe.VerificationFailure("unexpected_output_path", path=path))
            for path in sorted(expectations.keys() & observed_by_path.keys(), key=str.encode):
                expected_kind, expected_mode, expected_size, expected_hash = expectations[path]
                actual = observed_by_path[path]
                mismatch = actual.kind != expected_kind or actual.mode != expected_mode
                mismatch_detail: str | None = None
                if expected_kind == "file":
                    if actual.content_sha256 is None:
                        failures.append(
                            _safe.VerificationFailure(
                                "output_file_unreadable_or_oversized", path=path
                            )
                        )
                    mismatch = mismatch or actual.link_count != 1
                    if semantic_family:
                        if actual.kind == "file" and actual.content_sha256 is not None:
                            try:
                                payload, payload_metadata = _read_relative_regular(
                                    output_descriptor, path
                                )
                            except OSError as exc:
                                failures.append(
                                    _safe.VerificationFailure(
                                        "output_scan_error",
                                        path=path,
                                        detail=f"semantic_read:{type(exc).__name__}",
                                    )
                                )
                                mismatch = True
                            else:
                                payload_is_initial_entry = (
                                    stat.S_IMODE(payload_metadata.st_mode)
                                    == actual.mode
                                    and payload_metadata.st_size == actual.size
                                    and payload_metadata.st_mtime_ns
                                    == actual.mtime_ns
                                    and payload_metadata.st_nlink
                                    == actual.link_count
                                    and sha256(payload).hexdigest()
                                    == actual.content_sha256
                                )
                                if not payload_is_initial_entry:
                                    mismatch = True
                                    mismatch_detail = (
                                        "semantic read differs from initial scan"
                                    )
                                    failures.append(
                                        _safe.VerificationFailure(
                                            "output_scan_error",
                                            path=path,
                                            detail="semantic_read_not_initial_entry",
                                        )
                                    )
                                else:
                                    semantic_match, mismatch_detail = (
                                        _semantic_output_matches(
                                            self.family,
                                            payload,
                                            expected_payloads[path],
                                        )
                                    )
                                    mismatch = mismatch or not semantic_match
                        else:
                            mismatch = True
                    else:
                        mismatch = mismatch or (
                            actual.size != expected_size
                            or actual.content_sha256 != expected_hash
                        )
                if mismatch:
                    failures.append(
                        _safe.VerificationFailure(
                            "output_entry_mismatch",
                            path=path,
                            detail=mismatch_detail,
                        )
                    )

            observed_again, second_errors = _safe._scan_tree_descriptor(output_descriptor)
            for detail in second_errors:
                failures.append(
                    _safe.VerificationFailure("output_scan_error", detail=detail)
                )
            if observed_again != observed:
                failures.append(
                    _safe.VerificationFailure(
                        "output_scan_error", detail="output_changed_during_verification"
                    )
                )
            named_output = os.stat(
                OUTPUT_ROOT, dir_fd=root_descriptor, follow_symlinks=False
            )
            if (
                _safe._filesystem_snapshot(os.fstat(output_descriptor))
                != _safe._filesystem_snapshot(opened_output)
                or _safe._filesystem_snapshot(named_output)
                != _safe._filesystem_snapshot(opened_output)
            ):
                failures.append(
                    _safe.VerificationFailure(
                        "output_scan_error", detail="output_root_changed_during_scan"
                    )
                )
        except OSError as exc:
            failures.append(
                _safe.VerificationFailure("output_scan_error", detail=type(exc).__name__)
            )
            observed = ()
        finally:
            os.close(output_descriptor)

        final_current, final_input_errors = _safe._scan_tree_descriptor(
            root_descriptor,
            exclude_top_level=frozenset({OUTPUT_ROOT}),
            pinned_regulars=pinned_by_path,
        )
        for detail in final_input_errors:
            failures.append(_safe.VerificationFailure("tree_scan_error", detail=detail))
        if final_current != current:
            failures.append(
                _safe.VerificationFailure(
                    "tree_scan_error", detail="input_changed_during_verification"
                )
            )
        try:
            reopened_descriptor, reopened_metadata = _safe._open_absolute_directory_no_follow(
                instance.workspace
            )
        except OSError as exc:
            failures.append(
                _safe.VerificationFailure(
                    "tree_scan_error", detail=f"workspace_changed:{type(exc).__name__}"
                )
            )
        else:
            try:
                if (
                    _safe._filesystem_snapshot(os.fstat(root_descriptor))
                    != _safe._filesystem_snapshot(root_metadata)
                    or _safe._filesystem_snapshot(reopened_metadata)
                    != _safe._filesystem_snapshot(root_metadata)
                ):
                    failures.append(
                        _safe.VerificationFailure(
                            "tree_scan_error", detail="workspace_changed_during_verification"
                        )
                    )
            finally:
                os.close(reopened_descriptor)

        projection = [_observed_projection(entry) for entry in observed]
        return self._result(
            instance,
            failures,
            sum(entry.kind == "file" for entry in observed),
            _digest(projection),
        )

    @staticmethod
    def _result(
        instance: FamilyFixtureInstance,
        failures: list[_safe.VerificationFailure],
        observed_files: int | None,
        output_hash: str | None,
    ) -> FamilyVerificationResult:
        return FamilyVerificationResult(
            fixture_id=instance.descriptor.fixture_id,
            passed=not failures,
            failures=tuple(failures),
            expected_file_count=len(instance._expected),
            observed_file_count=observed_files,
            output_tree_sha256=output_hash,
        )


def public_development_suites(
    seed: int = DEFAULT_SEED,
) -> tuple[PublicStaticFamilySuite, ...]:
    """Return all non-executing public-development families in stable order."""

    return tuple(
        PublicStaticFamilySuite(family, seed=seed)
        for family in (COPY_MAP_FAMILY, CSV_TOTALS_FAMILY, CHECKSUM_MODE_FAMILY)
    )


__all__ = [
    "CHECKSUM_MODE_FAMILY",
    "CHECKSUM_MODE_PROMPT",
    "CONTRACT_VERSION",
    "COPY_MAP_FAMILY",
    "COPY_MAP_PROMPT",
    "CSV_TOTALS_FAMILY",
    "CSV_TOTALS_PROMPT",
    "DEFAULT_SEED",
    "FamilyDescriptor",
    "FamilyFixtureInstance",
    "FamilyMaterializationError",
    "FamilyVerificationError",
    "FamilyVerificationResult",
    "OUTPUT_DIRECTORY_MODE",
    "OUTPUT_FILE_MODE",
    "OUTPUT_ROOT",
    "PublicStaticFamilySuite",
    "SCHEMA_VERSION",
    "StaticFamilyError",
    "public_development_suites",
]
