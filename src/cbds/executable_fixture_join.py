"""Deterministic JSONL inner-join fixtures for public method development.

The generator owns both input streams and derives the trusted answer directly
from their immutable bytes.  Parsing is deliberately stricter than Python's
default JSON decoder: malformed UTF-8, duplicate object members, and every
noncanonical or unsafe number are rejected one line at a time.  No candidate
is executed.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
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
from .executable_static_types import (
    ExecutableStaticTask,
    JsonlKeyedInnerJoinParameters,
)
from .executable_workspace import (
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
)


JOIN_FIXTURE_GENERATOR_VERSION: Final[str] = "1.0.0"
OUTPUT_PATH: Final[str] = "output/joined.jsonl"
OUTPUT_MODE: Final[int] = 0o644
OUTPUT_MAXIMUM_BYTES: Final[int] = 256 * 1024
MAXIMUM_SAFE_JSON_INTEGER: Final[int] = 9_007_199_254_740_991


class ExecutableFixtureJoinError(ValueError):
    """Raised when a JSONL join fixture is outside its closed contract."""


class _RejectedJsonLine(ValueError):
    """Internal signal for one independently ignored JSONL record."""


@dataclass(frozen=True, slots=True)
class _AcceptedRecord:
    order: int
    key: str
    value: dict[str, object]


def _validate_task_profile(
    task: object, profile: object
) -> tuple[
    ExecutableStaticTask,
    ExecutableFixtureProfile,
    JsonlKeyedInnerJoinParameters,
]:
    if (
        type(task) is not ExecutableStaticTask
        or task.family_id != "jsonl-keyed-inner-join"
        or type(task.parameters) is not JsonlKeyedInnerJoinParameters
    ):
        raise ExecutableFixtureJoinError(
            "task must be an exact jsonl-keyed-inner-join ExecutableStaticTask"
        )
    if type(profile) is not ExecutableFixtureProfile:
        raise ExecutableFixtureJoinError(
            "profile must be an exact ExecutableFixtureProfile"
        )
    try:
        parameters = JsonlKeyedInnerJoinParameters(
            key=task.parameters.key,
            duplicate_policy=task.parameters.duplicate_policy,
        )
        task.__post_init__()
        reconstructed_profile = ExecutableFixtureProfile(
            profile_id=profile.profile_id,
            cases=profile.cases,
            profile_sha256=profile.profile_sha256,
            profile_version=profile.profile_version,
            public_method_development=profile.public_method_development,
            sealed=profile.sealed,
            candidate_execution_authorized=profile.candidate_execution_authorized,
            model_selection_eligible=profile.model_selection_eligible,
            claim_authorized=profile.claim_authorized,
        )
    except (TypeError, ValueError) as exc:
        raise ExecutableFixtureJoinError(
            "task or profile failed closed-contract revalidation"
        ) from exc
    if reconstructed_profile not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        raise ExecutableFixtureJoinError(
            "profile is not public method-development data"
        )
    return task, profile, parameters


def _input_json_line(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _valid_duplicate_streams(
    key_name: str,
    first_key: str,
    second_key: str,
    profile_marker: str,
) -> tuple[bytes, bytes]:
    left = (
        {"z": 2, key_name: first_key, "side": "left-0", "nested": {"b": 2, "a": 1}},
        {key_name: second_key, "side": "left-1", "items": [{"z": 0, "a": 1}]},
        {"side": "left-2", key_name: first_key, "marker": profile_marker},
        {key_name: "left-only", "side": "left-unmatched"},
    )
    right = (
        {key_name: first_key, "side": "right-0", "nested": {"d": 4, "c": 3}},
        {"side": "right-1", key_name: first_key, "marker": profile_marker},
        {key_name: second_key, "side": "right-2"},
        {key_name: "right-only", "side": "right-unmatched"},
    )
    return (
        b"\n".join(_input_json_line(value) for value in left) + b"\n",
        b"\n".join(_input_json_line(value) for value in right) + b"\n",
    )


def _malformed_stream(key_name: str, side: str) -> bytes:
    valid_a = _input_json_line(
        {key_name: "shared", "side": f"{side}-0", "nested": {"z": 1, "a": 2}}
    )
    valid_b = _input_json_line({"side": f"{side}-1", key_name: "shared"})
    valid_c = _input_json_line({key_name: "other", "side": f"{side}-2"})
    quoted_key = json.dumps(key_name).encode("ascii")
    duplicate_top = (
        b"{" + quoted_key + b':"bad-duplicate",' + quoted_key + b':"shared"}'
    )
    duplicate_nested = (
        b"{" + quoted_key + b':"shared","nested":{"x":1,"x":2}}'
    )
    bad_selected_values = (
        b"{" + quoted_key + b":7}",
        b"{" + quoted_key + b":null}",
        b"{" + quoted_key + b':"bad\\u0000key"}',
        b"{" + quoted_key + b':"bad\\rkey"}',
        b"{" + quoted_key + b':"bad\\nkey"}',
    )
    nonfinite = (
        b"{" + quoted_key + b':"shared","n":NaN}',
        b"{" + quoted_key + b':"shared","n":Infinity}',
        b"{" + quoted_key + b':"shared","n":-Infinity}',
        b"{" + quoted_key + b':"shared","n":1.5}',
        b"{" + quoted_key + b':"shared","n":1e2}',
        b"{" + quoted_key + b':"shared","n":-0}',
        b"{" + quoted_key + b':"shared","n":9007199254740992}',
        b"{" + quoted_key + b':"shared","n":1e999}',
    )
    lines = (
        b"",
        b"   ",
        valid_a,
        b"{",
        b"[]",
        b'"not-an-object"',
        b'{"unselected":"missing"}',
        *bad_selected_values,
        duplicate_top,
        duplicate_nested,
        *nonfinite,
        b'{"invalid":"\xff"}',
        valid_b,
        valid_c,
    )
    return b"\n".join(lines) + b"\n"


def _fixture_inputs(
    profile: ExecutableFixtureProfile,
    key_name: str,
) -> tuple[InputFile | InputSymlink, ...]:
    profile_id = profile.profile_id
    if profile_id == "spaces-unicode":
        left, right = _valid_duplicate_streams(
            key_name, "space key", '한글, "키"', "café 雪"
        )
        return (
            InputFile("input/left.jsonl", left, 0o640),
            InputFile("input/right.jsonl", right, 0o444),
        )
    if profile_id == "leading-dashes-globs":
        left, right = _valid_duplicate_streams(
            key_name, "-leading", "glob[*]?", "--literal-[*]?"
        )
        # Exact duplicate source records ensure that a Cartesian join contains
        # byte-identical output rows which must not be deduplicated.
        duplicate_left = _input_json_line(
            {key_name: "literal-duplicate", "side": "left-exact"}
        )
        duplicate_right = _input_json_line(
            {key_name: "literal-duplicate", "side": "right-exact"}
        )
        left += duplicate_left + b"\n" + duplicate_left + b"\n"
        right += duplicate_right + b"\n" + duplicate_right + b"\n"
        return (
            InputFile("input/left.jsonl", left, 0o604),
            InputFile("input/right.jsonl", right, 0o440),
        )
    if profile_id == "empty-duplicates":
        left_values = (
            {key_name: "", "side": "left-duplicate"},
            {"side": "left-duplicate", key_name: ""},
        )
        right_values = (
            {key_name: "right-only", "side": "right-duplicate"},
            {"side": "right-duplicate", key_name: "right-only"},
        )
        left = b"\n \n" + b"\n".join(map(_input_json_line, left_values)) + b"\n"
        right = b"\n\t\n" + b"\n".join(map(_input_json_line, right_values)) + b"\n"
        return (
            InputFile("input/left.jsonl", left, 0o400),
            InputFile("input/right.jsonl", right, 0o444),
        )
    if profile_id == "symlinks-ordering":
        left, right = _valid_duplicate_streams(
            key_name, "z-last", "a-first", "ordering"
        )
        # Deliberately noncanonical definition order; the extra link is not one
        # of the two named streams and therefore cannot affect the join.
        return (
            InputFile("input/right.jsonl", right, 0o444),
            InputSymlink("input/ignored-left-link.jsonl", "left.jsonl"),
            InputFile("input/left.jsonl", left, 0o640),
        )
    if profile_id == "partial-permissions":
        return (
            InputFile("input/left.jsonl", _malformed_stream(key_name, "left"), 0o400),
            InputFile("input/right.jsonl", _malformed_stream(key_name, "right"), 0o444),
            InputFile("input/ignored-unreadable.jsonl", b'{"ignored":true}\n', 0o000),
        )
    raise ExecutableFixtureJoinError("unsupported fixture profile")


def _reject_constant(_value: str) -> object:
    raise _RejectedJsonLine("non-finite JSON number")


def _reject_float(_value: str) -> object:
    raise _RejectedJsonLine("JSON number is not a canonical integer")


def _safe_integer(value: str) -> int:
    if len(value) > 17:
        raise _RejectedJsonLine("JSON integer is outside the safe range")
    parsed = int(value, 10)
    if (
        str(parsed) != value
        or not -MAXIMUM_SAFE_JSON_INTEGER <= parsed <= MAXIMUM_SAFE_JSON_INTEGER
    ):
        raise _RejectedJsonLine("JSON integer is not canonical and safe")
    return parsed


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _RejectedJsonLine("duplicate JSON object member")
        result[key] = value
    return result


def _accepted_records(content: bytes, key_name: str) -> tuple[_AcceptedRecord, ...]:
    accepted: list[_AcceptedRecord] = []
    for raw_line in content.split(b"\n"):
        if not raw_line.strip():
            continue
        try:
            line = raw_line.decode("utf-8", errors="strict")
            value = json.loads(
                line,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
                parse_float=_reject_float,
                parse_int=_safe_integer,
            )
            if type(value) is not dict:
                continue
            selected = value.get(key_name)
            if type(selected) is not str or any(
                character in selected for character in ("\0", "\r", "\n")
            ):
                continue
            # This also rejects isolated surrogate escapes that cannot be
            # represented by the required canonical UTF-8 output.
            _canonical_json(value)
        except (UnicodeDecodeError, UnicodeEncodeError, json.JSONDecodeError, _RejectedJsonLine):
            continue
        accepted.append(
            _AcceptedRecord(order=len(accepted), key=selected, value=value)
        )
    return tuple(accepted)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _derive_output(
    inputs: tuple[InputFile | InputSymlink, ...],
    parameters: JsonlKeyedInnerJoinParameters,
) -> bytes:
    regulars = {item.path: item for item in inputs if type(item) is InputFile}
    try:
        left_input = regulars["input/left.jsonl"]
        right_input = regulars["input/right.jsonl"]
    except KeyError as exc:  # pragma: no cover - closed internal construction
        raise ExecutableFixtureJoinError("fixture lacks a required JSONL stream") from exc
    left = _accepted_records(left_input.content, parameters.key)
    right = _accepted_records(right_input.content, parameters.key)

    left_by_key: dict[str, list[_AcceptedRecord]] = {}
    right_by_key: dict[str, list[_AcceptedRecord]] = {}
    for record in left:
        left_by_key.setdefault(record.key, []).append(record)
    for record in right:
        right_by_key.setdefault(record.key, []).append(record)

    rows: list[tuple[bytes, int, int, dict[str, object]]] = []
    for key in left_by_key.keys() & right_by_key.keys():
        selected_left = left_by_key[key]
        selected_right = right_by_key[key]
        policy = parameters.duplicate_policy
        if policy == "first-left":
            selected_left = selected_left[:1]
        elif policy == "last-left":
            selected_left = selected_left[-1:]
        elif policy == "first-right":
            selected_right = selected_right[:1]
        elif policy == "last-right":
            selected_right = selected_right[-1:]
        elif policy != "cartesian":  # pragma: no cover - parameter revalidation
            raise ExecutableFixtureJoinError("unsupported duplicate policy")
        for left_record in selected_left:
            for right_record in selected_right:
                rows.append(
                    (
                        key.encode("utf-8"),
                        left_record.order,
                        right_record.order,
                        {
                            "key": key,
                            "left": left_record.value,
                            "right": right_record.value,
                        },
                    )
                )
    rows.sort(key=lambda row: (row[0], row[1], row[2]))
    if not rows:
        return b""
    return b"\n".join(_canonical_json(row[3]) for row in rows) + b"\n"


def build_jsonl_keyed_inner_join_fixture_bundle(
    task: ExecutableStaticTask,
    profile: ExecutableFixtureProfile,
) -> ExecutableFixtureBundle:
    """Build one answer-bound join fixture without executing any process."""

    task, profile, parameters = _validate_task_profile(task, profile)
    inputs = _fixture_inputs(profile, parameters.key)
    content = _derive_output(inputs, parameters)
    if len(content) > OUTPUT_MAXIMUM_BYTES:
        raise ExecutableFixtureJoinError("derived JSONL join output exceeds its bound")
    output = OracleOutputRecord(OUTPUT_PATH, content, OUTPUT_MODE)
    definition = FixtureDefinition(
        fixture_id=f"dev.jsonl-keyed-inner-join.{profile.profile_id}",
        inputs=inputs,
        expected_files=(
            ExpectedFile(
                OUTPUT_PATH,
                maximum_bytes=OUTPUT_MAXIMUM_BYTES,
                mode=OUTPUT_MODE,
            ),
        ),
    )
    oracle = build_trusted_fixture_oracle(
        (output,),
        semantic_verifier_identity="verify-jsonl-keyed-inner-join-v1",
    )
    return build_executable_fixture_bundle(
        task_contract_sha256=task.task_contract_sha256,
        profile_sha256=profile.profile_sha256,
        definition=definition,
        oracle=oracle,
    )


__all__ = [
    "JOIN_FIXTURE_GENERATOR_VERSION",
    "ExecutableFixtureJoinError",
    "build_jsonl_keyed_inner_join_fixture_bundle",
]
