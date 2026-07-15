"""Non-executing audit of the released BashCoder-R1/BashBench artifact.

The upstream artifact contains natural-language tasks, generated reference
answers, shell test scripts, and Python harnesses.  None of those programs are
trusted by this module.  The audit opens a small, explicitly named projection
of an already extracted archive, parses JSON and Python syntax only, and
records whether the released files establish a usable candidate-to-verifier
handoff.  It never imports upstream Python or executes upstream shell text.

This audit is deliberately narrower than a benchmark adapter.  In particular,
``benchmark_eligible`` remains false: a future adapter must re-specify tasks,
review or replace every verifier, and run candidates in the project's pinned
sandbox before BashBench can support a research claim.
"""

from __future__ import annotations

import ast
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from hashlib import sha256
import json
import math
import os
from pathlib import PurePosixPath
import re
import stat
from typing import Any, Final


AUDIT_SCHEMA_VERSION: Final[str] = "1.0.0"
AUDITOR_VERSION: Final[str] = "1.0.0"
MAX_JSON_BYTES: Final[int] = 16 * 1024 * 1024
MAX_PYTHON_BYTES: Final[int] = 2 * 1024 * 1024

ZENODO_RECORD_ID: Final[int] = 18_408_692
ZENODO_RECORD_REVISION: Final[int] = 4
ZENODO_RECORD_URL: Final[str] = "https://zenodo.org/records/18408692"
ARCHIVE_KEY: Final[str] = "BashCoder-R1.zip"
ARCHIVE_SIZE_BYTES: Final[int] = 1_108_526_600
ARCHIVE_DECLARED_MD5: Final[str] = "e2cef192c89ee8f14fe4c59152f213bf"
ARCHIVE_LICENSE_ID: Final[str] = "cc-by-4.0"

COMMAND_EVALUATION: Final[str] = (
    "data/evaluation/command/evaluation_single-line_command.json"
)
SCRIPT_EVALUATION: Final[str] = (
    "data/evaluation/script/evaluation_multi-line_script.json"
)
COMMAND_TEST_CASES: Final[str] = "test_cases/command_test_cases_validated.json"
SCRIPT_TEST_CASES: Final[str] = "test_cases/script_test_cases_validated.json"
COMMAND_HARNESS: Final[str] = "test/test_our_command_general_LLMs.py"
SCRIPT_HARNESS: Final[str] = "test/test_our_script_general_LLMs.py"

REQUIRED_MEMBERS: Final[tuple[str, ...]] = (
    COMMAND_EVALUATION,
    SCRIPT_EVALUATION,
    COMMAND_TEST_CASES,
    SCRIPT_TEST_CASES,
    COMMAND_HARNESS,
    SCRIPT_HARNESS,
)

# Independently hashed after bounded ZIP-member extraction from Zenodo record
# 18408692, revision 4.  These hashes authenticate the selected projection,
# not the unextracted archive as a whole.
EXPECTED_RELEASE_V1_MEMBERS: Final[dict[str, tuple[int, str]]] = {
    COMMAND_EVALUATION: (
        1_688_265,
        "1531cd03579b7eb13dbb12c2a3198a032eadb961b8e221b0a47542b60a355c3f",
    ),
    SCRIPT_EVALUATION: (
        1_242_823,
        "803142cee32d0266c78bdc9f383cb804cd17e251bc0312a0e058d64045c67213",
    ),
    COMMAND_TEST_CASES: (
        2_888_568,
        "235bad3c762229ec49c2b72d480de1c7c0f3bda81b6b84a6bf6a0003170cccd8",
    ),
    SCRIPT_TEST_CASES: (
        1_348_605,
        "43bcfd071ee4981e009e6c1cdfecc4dbc9e94ef5b53fbcb58aa95db1869387eb",
    ),
    COMMAND_HARNESS: (
        40_129,
        "c4cca1bdda6d257480958016ececf0b228412c00e43e75119820d2ca4e4c9c46",
    ),
    SCRIPT_HARNESS: (
        33_169,
        "2fe2928a044c8a70f90aa36de1c746a2d008438a58996b6dad9b89474c46ece4",
    ),
}

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_MD5_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{32}\Z")
_CANDIDATE_LITERAL_RE: Final[re.Pattern[str]] = re.compile(
    r'''(?i)(?:^|[/\s'"])solution\.sh(?:$|[\s'"])'''
)
_POSITIONAL_PARAMETER_RE: Final[re.Pattern[str]] = re.compile(
    r"\$(?:[1-9]|\{[1-9]\})"
)
_NETWORK_OR_INSTALL_RE: Final[re.Pattern[str]] = re.compile(
    r"(?m)(?:^|[;&|()\s])(?:curl|wget|ssh|scp|nc|ncat|socat|"
    r"apt(?:-get)?|yum|dnf|pacman|brew)(?:$|\s)"
)
_PRIVILEGED_OR_SERVICE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?m)(?:^|[;&|()\s])(?:sudo|su|systemctl|service|launchctl|"
    r"mount|umount)(?:$|\s)"
)


class BashBenchAuditError(ValueError):
    """Raised when the selected upstream projection is malformed or unstable."""


@dataclass(frozen=True, slots=True)
class BashBenchSource:
    """Externally authenticated identity of the upstream Zenodo object."""

    record_id: int
    record_revision: int
    record_url: str
    archive_key: str
    archive_size_bytes: int
    archive_declared_md5: str
    license_id: str

    def __post_init__(self) -> None:
        if type(self.record_id) is not int or self.record_id != ZENODO_RECORD_ID:
            raise BashBenchAuditError("unexpected upstream record_id")
        if (
            type(self.record_revision) is not int
            or self.record_revision != ZENODO_RECORD_REVISION
        ):
            raise BashBenchAuditError("unexpected upstream record_revision")
        if self.record_url != ZENODO_RECORD_URL:
            raise BashBenchAuditError("unexpected upstream record_url")
        if self.archive_key != ARCHIVE_KEY:
            raise BashBenchAuditError("unexpected upstream archive key")
        if (
            type(self.archive_size_bytes) is not int
            or self.archive_size_bytes != ARCHIVE_SIZE_BYTES
        ):
            raise BashBenchAuditError("unexpected upstream archive_size_bytes")
        if (
            not isinstance(self.archive_declared_md5, str)
            or not _MD5_RE.fullmatch(self.archive_declared_md5)
            or self.archive_declared_md5 != ARCHIVE_DECLARED_MD5
        ):
            raise BashBenchAuditError("unexpected upstream archive_declared_md5")
        if self.license_id != ARCHIVE_LICENSE_ID:
            raise BashBenchAuditError("unexpected upstream license identity")

    @classmethod
    def release_v1(cls) -> BashBenchSource:
        """Return the frozen Zenodo identity used by this auditor."""

        return cls(
            record_id=ZENODO_RECORD_ID,
            record_revision=ZENODO_RECORD_REVISION,
            record_url=ZENODO_RECORD_URL,
            archive_key=ARCHIVE_KEY,
            archive_size_bytes=ARCHIVE_SIZE_BYTES,
            archive_declared_md5=ARCHIVE_DECLARED_MD5,
            license_id=ARCHIVE_LICENSE_ID,
        )

    def to_record(self) -> dict[str, object]:
        return {
            "record_id": self.record_id,
            "record_revision": self.record_revision,
            "record_url": self.record_url,
            "archive_key": self.archive_key,
            "archive_size_bytes": self.archive_size_bytes,
            "archive_declared_md5": self.archive_declared_md5,
            "archive_digest_source": "zenodo_record_metadata",
            "full_archive_digest_recomputed": False,
            "license_id": self.license_id,
        }


def canonical_json_bytes(value: object) -> bytes:
    """Canonical bytes used for all audit commitments."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def value_sha256(value: object) -> str:
    return sha256(canonical_json_bytes(value)).hexdigest()


def compute_bashbench_audit_sha256(report: Mapping[str, object]) -> str:
    """Hash the report while excluding its self-hash field."""

    core = dict(report)
    core.pop("audit_sha256", None)
    return value_sha256(core)


def verify_bashbench_audit_sha256(report: Mapping[str, object]) -> bool:
    declared = report.get("audit_sha256")
    return (
        isinstance(declared, str)
        and bool(_SHA256_RE.fullmatch(declared))
        and declared == compute_bashbench_audit_sha256(report)
    )


def _open_directory_at(parent: int, name: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    return os.open(name, flags, dir_fd=parent)


def _open_root(root: str | os.PathLike[str]) -> int:
    path = os.path.abspath(os.fspath(root))
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BashBenchAuditError("cannot open extracted artifact root") from exc
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise BashBenchAuditError("extracted artifact root is not a directory")
    return descriptor


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


def _read_member(root_descriptor: int, path_text: str, maximum: int) -> bytes:
    path = PurePosixPath(path_text)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise BashBenchAuditError(f"unsafe member path: {path_text!r}")
    directory = os.dup(root_descriptor)
    try:
        for part in path.parts[:-1]:
            opened = _open_directory_at(directory, part)
            os.close(directory)
            directory = opened
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path.parts[-1], flags, dir_fd=directory)
        try:
            before = os.fstat(descriptor)
            named_before = os.stat(path.parts[-1], dir_fd=directory, follow_symlinks=False)
            if (
                not stat.S_ISREG(before.st_mode)
                or _fingerprint(before) != _fingerprint(named_before)
                or before.st_size < 0
                or before.st_size > maximum
            ):
                raise BashBenchAuditError(f"member is not a stable bounded regular file: {path_text}")
            chunks: list[bytes] = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    raise BashBenchAuditError(f"member ended early: {path_text}")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise BashBenchAuditError(f"member grew while reading: {path_text}")
            after = os.fstat(descriptor)
            named_after = os.stat(path.parts[-1], dir_fd=directory, follow_symlinks=False)
            if _fingerprint(before) != _fingerprint(after) or _fingerprint(after) != _fingerprint(named_after):
                raise BashBenchAuditError(f"member changed while reading: {path_text}")
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except FileNotFoundError as exc:
        raise BashBenchAuditError(f"required member is missing: {path_text}") from exc
    except OSError as exc:
        raise BashBenchAuditError(f"cannot read required member: {path_text}") from exc
    finally:
        os.close(directory)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BashBenchAuditError(f"JSON contains duplicate key: {key!r}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise BashBenchAuditError(f"JSON contains non-finite number: {value}")


def _load_json(payload: bytes, label: str) -> list[dict[str, Any]]:
    try:
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BashBenchAuditError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise BashBenchAuditError(f"{label} must be a list of objects")
    return value


def _required_text(record: Mapping[str, Any], field: str, label: str) -> str:
    value = record.get(field)
    if not isinstance(value, str):
        raise BashBenchAuditError(f"{label}.{field} must be a string")
    return value


def _categorical(values: Iterable[object]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for value in values:
        if value is True:
            key = "true"
        elif value is False:
            key = "false"
        elif value is None:
            key = "null"
        else:
            key = f"other:{type(value).__name__}"
        counts[key] += 1
    return dict(sorted(counts.items()))


def _duplicate_summary(values: list[str]) -> dict[str, int]:
    counts = Counter(values)
    duplicate_groups = [count for count in counts.values() if count > 1]
    return {
        "records": len(values),
        "unique_values": len(counts),
        "duplicate_records_beyond_first": len(values) - len(counts),
        "duplicate_groups": len(duplicate_groups),
        "maximum_multiplicity": max(counts.values(), default=0),
    }


def _sample_id_summary(records: list[dict[str, Any]]) -> dict[str, object]:
    integers = [
        item.get("sample_id")
        for item in records
        if type(item.get("sample_id")) is int
    ]
    return {
        "integer_ids": len(integers),
        "unique_integer_ids": len(set(integers)),
        "minimum_integer_id": min(integers) if integers else None,
        "maximum_integer_id": max(integers) if integers else None,
        "id_equals_list_index": sum(value == index for index, value in enumerate(integers))
        if len(integers) == len(records)
        else 0,
    }


def _test_script(record: Mapping[str, Any]) -> str | None:
    value = record.get("test_case")
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise BashBenchAuditError("test_case must be an object or null")
    script = value.get("test_script")
    if not isinstance(script, str):
        raise BashBenchAuditError("test_case.test_script must be a string")
    return script


def _test_case_summary(records: list[dict[str, Any]]) -> dict[str, object]:
    scripts = [_test_script(item) for item in records]
    present = [script for script in scripts if script]
    safe_values = [
        None if item.get("test_case") is None else item["test_case"].get("is_safe_to_execute")
        for item in records
    ]
    return {
        "records": len(records),
        "sample_ids": _sample_id_summary(records),
        "validated_values": _categorical(item.get("validated") for item in records),
        "test_case_presence": {
            "present_nonempty": len(present),
            "missing_or_empty": len(records) - len(present),
        },
        "is_safe_to_execute_values": _categorical(safe_values),
        "candidate_handoff_scan": {
            "literal_solution_sh_references": sum(
                bool(_CANDIDATE_LITERAL_RE.search(script)) for script in present
            ),
            "positional_parameter_lexeme_scripts": sum(
                bool(_POSITIONAL_PARAMETER_RE.search(script)) for script in present
            ),
            "scripts_with_test_passed_marker": sum("TEST_PASSED" in script for script in present),
        },
        "risk_lexemes": {
            "network_or_package_tool_scripts": sum(
                bool(_NETWORK_OR_INSTALL_RE.search(script)) for script in present
            ),
            "privileged_or_service_tool_scripts": sum(
                bool(_PRIVILEGED_OR_SERVICE_RE.search(script)) for script in present
            ),
        },
    }


def _alignment_summary(
    evaluation: list[dict[str, Any]], tests: list[dict[str, Any]], label: str
) -> dict[str, object]:
    evaluation_inputs = [
        _required_text(item, "input", f"{label}.evaluation[{index}]")
        for index, item in enumerate(evaluation)
    ]
    test_inputs = [
        _required_text(item, "input", f"{label}.tests[{index}]")
        for index, item in enumerate(tests)
    ]
    evaluation_set = set(evaluation_inputs)
    test_set = set(test_inputs)
    paired = min(len(evaluation_inputs), len(test_inputs))
    index_matches = sum(
        evaluation_inputs[index] == test_inputs[index] for index in range(paired)
    )
    one_to_one = (
        len(evaluation_inputs) == len(test_inputs)
        and len(evaluation_set) == len(evaluation_inputs)
        and len(test_set) == len(test_inputs)
        and index_matches == len(evaluation_inputs)
    )
    return {
        "evaluation_records": len(evaluation_inputs),
        "test_records": len(test_inputs),
        "evaluation_prompt_duplicates": _duplicate_summary(evaluation_inputs),
        "test_prompt_duplicates": _duplicate_summary(test_inputs),
        "index_aligned_prompt_matches": index_matches,
        "index_compared_records": paired,
        "test_records_with_prompt_anywhere_in_evaluation": sum(
            value in evaluation_set for value in test_inputs
        ),
        "unique_prompt_intersection": len(evaluation_set & test_set),
        "unique_evaluation_only": len(evaluation_set - test_set),
        "unique_test_only": len(test_set - evaluation_set),
        "one_to_one_index_identity": one_to_one,
    }


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _argument_shape(node: ast.AST) -> object:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, bool, type(None))):
        return node.value
    if isinstance(node, ast.Name):
        return {"name": node.id}
    if isinstance(node, (ast.List, ast.Tuple)):
        return [_argument_shape(item) for item in node.elts]
    if isinstance(node, ast.Call):
        return {
            "call": _call_name(node.func),
            "arguments": [_argument_shape(item) for item in node.args],
            "keyword_names": sorted(
                keyword.arg for keyword in node.keywords if keyword.arg
            ),
        }
    return {"node": type(node).__name__}


def _is_direct_bash_test_path_invocation(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    first_argument = value.get("first_argument")
    if not isinstance(first_argument, list) or len(first_argument) != 2:
        return False
    test_path_shapes: tuple[object, ...] = (
        {"name": "test_path"},
        {
            "call": "str",
            "arguments": [{"name": "test_path"}],
            "keyword_names": [],
        },
    )
    return (
        value.get("callee") == "subprocess.run"
        and first_argument[0] == "bash"
        and first_argument[1] in test_path_shapes
    )


def _harness_summary(payload: bytes, label: str) -> dict[str, object]:
    try:
        text = payload.decode("utf-8", errors="strict")
        tree = ast.parse(text, filename=f"<{label}>", mode="exec")
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise BashBenchAuditError(f"{label} is not parseable UTF-8 Python") from exc

    execute_functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "execute_test_script"
    ]
    invocations: list[dict[str, object]] = []
    for function in execute_functions:
        for node in ast.walk(function):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node.func)
            if name not in {"subprocess.run", "subprocess.Popen"}:
                continue
            invocations.append(
                {
                    "callee": name,
                    "first_argument": _argument_shape(node.args[0]) if node.args else None,
                    "keyword_names": sorted(keyword.arg for keyword in node.keywords if keyword.arg),
                }
            )
    invocations.sort(key=canonical_json_bytes)
    return {
        "python_ast_parsed": True,
        "execute_test_script_definitions": len(execute_functions),
        "execute_test_script_subprocess_invocations": invocations,
        "source_mentions_solution_sh": text.count("solution.sh"),
        "source_mentions_bwrap": text.count("bwrap"),
        "source_mentions_podman": text.count("podman"),
        "source_mentions_docker": text.count("docker"),
    }


def audit_bashbench_projection(
    root: str | os.PathLike[str], *, source: BashBenchSource
) -> dict[str, object]:
    """Audit an extracted six-member BashBench projection without execution."""

    root_descriptor = _open_root(root)
    try:
        payloads: dict[str, bytes] = {}
        for path in REQUIRED_MEMBERS:
            maximum = MAX_PYTHON_BYTES if path.endswith(".py") else MAX_JSON_BYTES
            payloads[path] = _read_member(root_descriptor, path, maximum)
    finally:
        os.close(root_descriptor)

    command_evaluation = _load_json(payloads[COMMAND_EVALUATION], "command evaluation")
    script_evaluation = _load_json(payloads[SCRIPT_EVALUATION], "script evaluation")
    command_tests = _load_json(payloads[COMMAND_TEST_CASES], "command tests")
    script_tests = _load_json(payloads[SCRIPT_TEST_CASES], "script tests")

    command_test_summary = _test_case_summary(command_tests)
    script_test_summary = _test_case_summary(script_tests)
    command_harness = _harness_summary(payloads[COMMAND_HARNESS], "command harness")
    script_harness = _harness_summary(payloads[SCRIPT_HARNESS], "script harness")

    explicit_candidate_references = sum(
        int(summary["candidate_handoff_scan"]["literal_solution_sh_references"])
        for summary in (command_test_summary, script_test_summary)
    )
    direct_test_only_launches = all(
        harness["execute_test_script_definitions"] == 1
        and len(harness["execute_test_script_subprocess_invocations"]) == 1
        and _is_direct_bash_test_path_invocation(
            harness["execute_test_script_subprocess_invocations"][0]
        )
        for harness in (command_harness, script_harness)
    )

    members = [
        {
            "path": path,
            "size_bytes": len(payloads[path]),
            "sha256": sha256(payloads[path]).hexdigest(),
        }
        for path in REQUIRED_MEMBERS
    ]
    expected_members = [
        {
            "path": path,
            "size_bytes": EXPECTED_RELEASE_V1_MEMBERS[path][0],
            "sha256": EXPECTED_RELEASE_V1_MEMBERS[path][1],
        }
        for path in REQUIRED_MEMBERS
    ]
    release_projection_authenticated = members == expected_members
    command_alignment = _alignment_summary(
        command_evaluation, command_tests, "command"
    )
    script_alignment = _alignment_summary(script_evaluation, script_tests, "script")
    findings: list[dict[str, str]] = []
    if not release_projection_authenticated:
        findings.append(
            {
                "code": "selected_projection_not_release_v1_authenticated",
                "severity": "blocking",
                "evidence": (
                    "At least one selected member does not match the independently "
                    "recorded release-v1 size and SHA-256. Release-specific findings "
                    "must not be attributed to this projection."
                ),
            }
        )
    if (
        explicit_candidate_references == 0
        and direct_test_only_launches
    ):
        findings.append(
            {
                "code": "released_candidate_handoff_not_proven",
                "severity": "blocking",
                "evidence": (
                    "Both selected harnesses write a solution.sh file but their "
                    "execute_test_script path launches bash test_path. Across the "
                    "selected test scripts, no literal solution.sh reference was "
                    "found, and the harness supplies no candidate argument. Static "
                    "evidence therefore does not establish that functional outcomes "
                    "depend on candidate code."
                ),
            }
        )
    if not (
        command_alignment["one_to_one_index_identity"]
        and script_alignment["one_to_one_index_identity"]
    ):
        findings.append(
            {
                "code": "released_counts_and_alignment_disagree",
                "severity": "blocking",
                "evidence": (
                    "Evaluation rows, test rows, unique prompts, sample IDs, and "
                    "index-aligned prompts do not form one one-to-one task identity."
                ),
            }
        )
    if direct_test_only_launches:
        findings.append(
            {
                "code": "released_execute_path_is_direct_subprocess",
                "severity": "blocking",
                "evidence": (
                    "The selected execute_test_script functions invoke the test file "
                    "as a direct `bash test_path` subprocess. The selected execution "
                    "path does not itself establish an OS isolation boundary; an "
                    "external caller could still wrap the entire harness."
                ),
            }
        )
    report: dict[str, object] = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "record_type": "cbds.bashbench-release-audit",
        "auditor_version": AUDITOR_VERSION,
        "source": source.to_record(),
        "member_projection": {
            "member_count": len(members),
            "members": members,
            "selected_member_set_sha256": value_sha256(members),
            "expected_release_v1_members": expected_members,
            "expected_release_v1_member_set_sha256": value_sha256(expected_members),
            "all_members_match_expected_release_v1": release_projection_authenticated,
            "archive_crc_members_rechecked_during_extraction": False,
        },
        "released_data": {
            "command": {
                "alignment": command_alignment,
                "tests": command_test_summary,
            },
            "script": {
                "alignment": script_alignment,
                "tests": script_test_summary,
            },
        },
        "released_harness": {
            "command": command_harness,
            "script": script_harness,
            "candidate_handoff": {
                "literal_solution_sh_references_across_test_scripts": explicit_candidate_references,
                "harness_candidate_arguments_after_test_path": 0
                if direct_test_only_launches
                else None,
                "both_harnesses_launch_only_bash_test_path": direct_test_only_launches,
                "candidate_handoff_proven": False,
            },
        },
        "findings": findings,
        "decision": {
            "status": "diagnostic_only_released_harness_rejected",
            "benchmark_eligible": False,
            "candidate_execution_authorized": False,
            "model_selection_authorized": False,
            "claim_authorized": False,
            "required_follow_up": [
                "derive one typed task identity shared by prompts and tests",
                "independently review and mutation-test every verifier",
                "make candidate handoff explicit and prove candidate dependence",
                "port fixtures and checks into the pinned project sandbox",
                "exclude the harness-audit subset before scored use",
            ],
        },
        "limitations": [
            "This is a non-executing audit of six selected archive members.",
            "The Zenodo MD5 is recorded from metadata; the full archive digest was not recomputed.",
            "Static scans cannot rule out every indirect shell data flow.",
            "No upstream test script, reference answer, generated program, or Python module was executed or imported.",
            "This report does not measure any model or benchmark pass rate.",
        ],
        "audit_hash_scope": "canonical_json_excluding_audit_sha256",
    }
    report["audit_sha256"] = compute_bashbench_audit_sha256(report)
    return report


def validate_bashbench_audit_report(
    report: object, *, require_authenticated_projection: bool = False
) -> dict[str, object]:
    """Fail closed on a serialized report before it is used as provenance."""

    if not isinstance(report, Mapping):
        raise BashBenchAuditError("audit report must be an object")
    value = dict(report)
    _validate_json_tree(value, label="audit report")
    required = {
        "schema_version",
        "record_type",
        "auditor_version",
        "source",
        "member_projection",
        "released_data",
        "released_harness",
        "findings",
        "decision",
        "limitations",
        "audit_hash_scope",
        "audit_sha256",
    }
    if set(value) != required:
        raise BashBenchAuditError("audit report keys are not exact")
    if (
        value["schema_version"] != AUDIT_SCHEMA_VERSION
        or value["record_type"] != "cbds.bashbench-release-audit"
        or value["auditor_version"] != AUDITOR_VERSION
        or value["audit_hash_scope"] != "canonical_json_excluding_audit_sha256"
    ):
        raise BashBenchAuditError("audit report identity is invalid")

    expected_source = BashBenchSource.release_v1().to_record()
    if value.get("source") != expected_source:
        raise BashBenchAuditError("audit source identity is invalid")

    projection = value.get("member_projection")
    projection_keys = {
        "member_count",
        "members",
        "selected_member_set_sha256",
        "expected_release_v1_members",
        "expected_release_v1_member_set_sha256",
        "all_members_match_expected_release_v1",
        "archive_crc_members_rechecked_during_extraction",
    }
    if not isinstance(projection, Mapping) or set(projection) != projection_keys:
        raise BashBenchAuditError("audit member projection is malformed")
    members = projection.get("members")
    if not isinstance(members, list) or len(members) != len(REQUIRED_MEMBERS):
        raise BashBenchAuditError("audit observed member list is malformed")
    for index, (member, path) in enumerate(zip(members, REQUIRED_MEMBERS, strict=True)):
        if (
            not isinstance(member, Mapping)
            or set(member) != {"path", "size_bytes", "sha256"}
            or member.get("path") != path
            or type(member.get("size_bytes")) is not int
            or int(member["size_bytes"]) < 0
            or not isinstance(member.get("sha256"), str)
            or _SHA256_RE.fullmatch(str(member["sha256"])) is None
        ):
            raise BashBenchAuditError(f"audit observed member {index} is malformed")
    expected_members = [
        {
            "path": path,
            "size_bytes": EXPECTED_RELEASE_V1_MEMBERS[path][0],
            "sha256": EXPECTED_RELEASE_V1_MEMBERS[path][1],
        }
        for path in REQUIRED_MEMBERS
    ]
    if projection.get("member_count") != len(REQUIRED_MEMBERS):
        raise BashBenchAuditError("audit member_count is invalid")
    if projection.get("selected_member_set_sha256") != value_sha256(members):
        raise BashBenchAuditError("audit selected member commitment is invalid")
    if projection.get("expected_release_v1_members") != expected_members:
        raise BashBenchAuditError("audit expected release member identities are invalid")
    if projection.get("expected_release_v1_member_set_sha256") != value_sha256(
        expected_members
    ):
        raise BashBenchAuditError("audit expected member commitment is invalid")
    authenticated = members == expected_members
    if projection.get("all_members_match_expected_release_v1") is not authenticated:
        raise BashBenchAuditError("audit member authentication result is invalid")
    if projection.get("archive_crc_members_rechecked_during_extraction") is not False:
        raise BashBenchAuditError("audit cannot attest archive extraction CRC")
    if require_authenticated_projection and not authenticated:
        raise BashBenchAuditError("audit projection is not authenticated to release v1")

    released_harness = value.get("released_harness")
    if not isinstance(released_harness, Mapping) or set(released_harness) != {
        "command",
        "script",
        "candidate_handoff",
    }:
        raise BashBenchAuditError("audit harness evidence is malformed")
    candidate_handoff = released_harness.get("candidate_handoff")
    if not isinstance(candidate_handoff, Mapping) or set(candidate_handoff) != {
        "literal_solution_sh_references_across_test_scripts",
        "harness_candidate_arguments_after_test_path",
        "both_harnesses_launch_only_bash_test_path",
        "candidate_handoff_proven",
    }:
        raise BashBenchAuditError("audit candidate handoff evidence is malformed")
    if candidate_handoff.get("candidate_handoff_proven") is not False:
        raise BashBenchAuditError("static audit cannot prove candidate handoff")

    findings = value.get("findings")
    if not isinstance(findings, list) or not findings:
        raise BashBenchAuditError("audit findings are malformed")
    finding_codes: set[str] = set()
    for finding in findings:
        if (
            not isinstance(finding, Mapping)
            or set(finding) != {"code", "severity", "evidence"}
            or not isinstance(finding.get("code"), str)
            or not finding.get("code")
            or finding.get("severity") != "blocking"
            or not isinstance(finding.get("evidence"), str)
            or not finding.get("evidence")
            or finding["code"] in finding_codes
        ):
            raise BashBenchAuditError("audit finding is malformed")
        finding_codes.add(str(finding["code"]))

    if authenticated:
        _validate_authenticated_release_facts(value, finding_codes=finding_codes)

    decision = value.get("decision")
    if not isinstance(decision, Mapping) or set(decision) != {
        "status",
        "benchmark_eligible",
        "candidate_execution_authorized",
        "model_selection_authorized",
        "claim_authorized",
        "required_follow_up",
    }:
        raise BashBenchAuditError("audit decision is malformed")
    if any(
        decision.get(name) is not False
        for name in (
            "benchmark_eligible",
            "candidate_execution_authorized",
            "model_selection_authorized",
            "claim_authorized",
        )
    ):
        raise BashBenchAuditError("released audit cannot authorize research use")
    if decision.get("status") != "diagnostic_only_released_harness_rejected":
        raise BashBenchAuditError("audit decision status is invalid")
    follow_up = decision.get("required_follow_up")
    if (
        not isinstance(follow_up, list)
        or not follow_up
        or any(not isinstance(item, str) or not item for item in follow_up)
        or len(follow_up) != len(set(follow_up))
    ):
        raise BashBenchAuditError("audit follow-up list is invalid")
    limitations = value.get("limitations")
    if (
        not isinstance(limitations, list)
        or not limitations
        or any(not isinstance(item, str) or not item for item in limitations)
    ):
        raise BashBenchAuditError("audit limitations are malformed")
    if not verify_bashbench_audit_sha256(value):
        raise BashBenchAuditError("audit self-hash does not verify")
    return value


def _validate_authenticated_release_facts(
    report: Mapping[str, object], *, finding_codes: set[str]
) -> None:
    """Freeze the release facts on which the checked rejection depends."""

    try:
        released_data = report["released_data"]
        command = released_data["command"]
        script = released_data["script"]
        command_alignment = command["alignment"]
        script_alignment = script["alignment"]
        command_tests = command["tests"]
        script_tests = script["tests"]
        handoff = report["released_harness"]["candidate_handoff"]
        command_harness = report["released_harness"]["command"]
        script_harness = report["released_harness"]["script"]
    except (AttributeError, KeyError, TypeError) as exc:
        raise BashBenchAuditError(
            "authenticated release evidence is incomplete"
        ) from exc

    if any(
        not isinstance(item, Mapping)
        for item in (
            released_data,
            command,
            script,
            command_alignment,
            script_alignment,
            command_tests,
            script_tests,
            handoff,
            command_harness,
            script_harness,
        )
    ):
        raise BashBenchAuditError("authenticated release evidence is malformed")
    command_duplicates = command_alignment.get("evaluation_prompt_duplicates")
    if not isinstance(command_duplicates, Mapping):
        raise BashBenchAuditError("authenticated release duplicate evidence is malformed")

    critical_values = (
        command_alignment.get("evaluation_records"),
        command_alignment.get("test_records"),
        command_duplicates.get("unique_values"),
        command_alignment.get("index_aligned_prompt_matches"),
        command_alignment.get("unique_prompt_intersection"),
        command_alignment.get("one_to_one_index_identity"),
        command_tests.get("test_case_presence"),
        command_tests.get("is_safe_to_execute_values"),
        script_alignment.get("evaluation_records"),
        script_alignment.get("test_records"),
        script_alignment.get("index_aligned_prompt_matches"),
        script_alignment.get("unique_prompt_intersection"),
        script_alignment.get("one_to_one_index_identity"),
        script_tests.get("test_case_presence"),
        script_tests.get("is_safe_to_execute_values"),
    )
    expected_values = (
        927,
        927,
        717,
        925,
        716,
        False,
        {"present_nonempty": 773, "missing_or_empty": 154},
        {"true": 773, "null": 154},
        179,
        154,
        2,
        40,
        False,
        {"present_nonempty": 154, "missing_or_empty": 0},
        {"true": 40, "false": 114},
    )
    if critical_values != expected_values:
        raise BashBenchAuditError(
            "authenticated release task/count evidence is invalid"
        )

    expected_handoff = {
        "literal_solution_sh_references_across_test_scripts": 0,
        "harness_candidate_arguments_after_test_path": 0,
        "both_harnesses_launch_only_bash_test_path": True,
        "candidate_handoff_proven": False,
    }
    if handoff != expected_handoff:
        raise BashBenchAuditError(
            "authenticated release candidate-handoff evidence is invalid"
        )
    expected_command_invocations = [
        {
            "callee": "subprocess.run",
            "first_argument": ["bash", {"name": "test_path"}],
            "keyword_names": ["capture_output", "cwd", "env", "text", "timeout"],
        }
    ]
    expected_script_invocations = [
        {
            "callee": "subprocess.run",
            "first_argument": [
                "bash",
                {
                    "call": "str",
                    "arguments": [{"name": "test_path"}],
                    "keyword_names": [],
                },
            ],
            "keyword_names": ["capture_output", "cwd", "env", "text", "timeout"],
        }
    ]
    if (
        command_harness.get("execute_test_script_definitions") != 1
        or script_harness.get("execute_test_script_definitions") != 1
        or command_harness.get("execute_test_script_subprocess_invocations")
        != expected_command_invocations
        or script_harness.get("execute_test_script_subprocess_invocations")
        != expected_script_invocations
    ):
        raise BashBenchAuditError(
            "authenticated release harness AST evidence is invalid"
        )
    if finding_codes != {
        "released_candidate_handoff_not_proven",
        "released_counts_and_alignment_disagree",
        "released_execute_path_is_direct_subprocess",
    }:
        raise BashBenchAuditError("authenticated release findings are invalid")


def _validate_json_tree(value: object, *, label: str) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if type(value) is int:
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise BashBenchAuditError(f"{label} contains a non-finite float")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_tree(item, label=label)
        return
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise BashBenchAuditError(f"{label} contains a non-string object key")
        for item in value.values():
            _validate_json_tree(item, label=label)
        return
    raise BashBenchAuditError(f"{label} contains a non-JSON value")


__all__ = [
    "AUDIT_SCHEMA_VERSION",
    "AUDITOR_VERSION",
    "BashBenchAuditError",
    "BashBenchSource",
    "REQUIRED_MEMBERS",
    "audit_bashbench_projection",
    "canonical_json_bytes",
    "compute_bashbench_audit_sha256",
    "validate_bashbench_audit_report",
    "value_sha256",
    "verify_bashbench_audit_sha256",
]
