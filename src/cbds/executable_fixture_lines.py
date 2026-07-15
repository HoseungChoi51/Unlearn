"""Deterministic private fixtures for the two line-output static families.

The public registry exposes only opaque profile commitments.  This module
materializes those commitments into answer-free workspace definitions and
trusted line oracles for ``active-jsonl-labels`` and
``path-suffix-inventory``.  Oracle bytes are derived by parsing the generated
input bytes and metadata; no candidate, shell, or verifier process is run.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
import json
from pathlib import PurePosixPath
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
    ActiveJsonlLabelsParameters,
    ExecutableStaticTask,
    PathSuffixInventoryParameters,
)
from .executable_workspace import (
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
)


LINE_FIXTURE_GENERATOR_VERSION: Final[str] = "1.0.0"
_ACTIVE_OUTPUT: Final[str] = "output/labels.txt"
_PATH_OUTPUT: Final[str] = "output/paths.txt"
_OUTPUT_MODE: Final[int] = 0o644
_ALL_SUFFIXES: Final[tuple[str, ...]] = (".txt", ".jsonl", ".log", ".csv")


class ExecutableFixtureLineError(ValueError):
    """Raised when a task/profile pair is not an exact supported contract."""


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant: {value}")


def _json_line(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _active_row(
    marker: str,
    *,
    active: bool = False,
    enabled: str = "no",
    state: str = "waiting",
    score: int | float = 0,
    deleted: bool = True,
    labels: dict[str, str] | None = None,
) -> dict[str, object]:
    selected_labels = {
        "label": marker,
        "name": f"name {marker}",
        "tag": f"tag-{marker}",
        "title": f"Title {marker}",
    }
    if labels is not None:
        selected_labels.update(labels)
    return {
        **selected_labels,
        "active": active,
        "enabled": enabled,
        "state": state,
        "score": score,
        "deleted": deleted,
    }


def _all_predicates_row(
    marker: str, *, labels: dict[str, str] | None = None
) -> dict[str, object]:
    return _active_row(
        marker,
        active=True,
        enabled="yes",
        state="ready",
        score=10,
        deleted=False,
        labels=labels,
    )


def _active_valid_rows(profile_id: str) -> list[dict[str, object]]:
    rows = [
        _all_predicates_row("common"),
        _active_row("decimal-score", score=10.5),
        _active_row("active-only", active=True),
        _active_row("enabled-only", enabled="yes"),
        _active_row("state-only", state="ready"),
        _active_row("score-only", score=11),
        _active_row("deleted-only", deleted=False),
    ]
    if profile_id == "spaces-unicode":
        rows.extend(
            (
                _all_predicates_row(
                    "spaces",
                    labels={
                        "label": "space label",
                        "name": "name with spaces",
                        "tag": "tag with spaces",
                        "title": "Title With Spaces",
                    },
                ),
                _all_predicates_row(
                    "unicode",
                    labels={
                        "label": "éclair",
                        "name": "이름",
                        "tag": "タグ",
                        "title": "雪",
                    },
                ),
            )
        )
    elif profile_id == "leading-dashes-globs":
        rows.extend(
            (
                _all_predicates_row(
                    "dash",
                    labels={key: f"-dash-{key}" for key in ("label", "name", "tag", "title")},
                ),
                _all_predicates_row(
                    "glob",
                    labels={key: f"[glob]*?-{key}" for key in ("label", "name", "tag", "title")},
                ),
            )
        )
    elif profile_id == "symlinks-ordering":
        rows.extend(
            (
                _all_predicates_row("zulu"),
                _all_predicates_row("Alpha"),
                _all_predicates_row("äther"),
            )
        )
    elif profile_id == "partial-permissions":
        rows.append(_all_predicates_row("readable-survivor"))
    elif profile_id == "empty-duplicates":
        # Keep duplicate valid records for the other label axes while making
        # every selected title non-line-safe.  Title tasks therefore exercise
        # the exact zero-byte output contract.
        for row in rows:
            row["title"] = "not\na-line"
    return rows


def _malformed_active_lines() -> bytes:
    # Duplicate object member names are intentionally absent: the task prompt
    # does not define their semantics and the allowed jq parser keeps the last
    # value.  Public fixtures must not silently impose a stricter parser policy.
    invalid_labels = _all_predicates_row(
        "invalid-labels",
        labels={
            "label": "not\na-line",
            "name": "contains\0nul",
            "tag": "contains\rcarriage",
            "title": "not\na-title",
        },
    )
    wrong_predicate_types = _active_row("wrong-predicate-types")
    wrong_predicate_types.update(
        {
            "active": "true",
            "enabled": True,
            "state": ["ready"],
            "score": True,
            "deleted": 0,
        }
    )
    return b"".join(
        (
            b"\n",
            b"{not-json}\n",
            b"[1,2,3]\n",
            b"null\n",
            b'{"score":NaN,"label":"not-finite"}\n',
            _json_line(invalid_labels),
            _json_line(wrong_predicate_types),
        )
    )


_ACTIVE_PATHS: Final[dict[str, tuple[str, str]]] = {
    "spaces-unicode": (
        "input/records/space dir/équipe.jsonl",
        "input/records/second file.jsonl",
    ),
    "leading-dashes-globs": (
        "input/records/-primary.jsonl",
        "input/records/[glob]*?.jsonl",
    ),
    "empty-duplicates": (
        "input/records/duplicates.jsonl",
        "input/records/empty.jsonl",
    ),
    "symlinks-ordering": (
        "input/records/z-last.jsonl",
        "input/records/a-first.jsonl",
    ),
    "partial-permissions": (
        "input/records/readable.jsonl",
        "input/records/malformed.jsonl",
    ),
}


def _active_inputs(profile: ExecutableFixtureProfile) -> tuple[InputFile | InputSymlink, ...]:
    rows = _active_valid_rows(profile.profile_id)
    encoded = [_json_line(row) for row in rows]
    midpoint = max(1, len(encoded) // 2)
    first_content = b"".join(encoded[:midpoint]) + _malformed_active_lines()
    second_content = b"".join(encoded[midpoint:])
    if profile.profile_id == "empty-duplicates":
        first_content += _json_line(rows[0]) + _json_line(rows[0])
        second_content = b""
    elif profile.profile_id == "partial-permissions":
        second_content += _malformed_active_lines()

    primary_path, secondary_path = _ACTIVE_PATHS[profile.profile_id]
    sentinel = _json_line(
        _all_predicates_row(
            "ignored",
            labels={
                "label": "IGNORED-LABEL",
                "name": "IGNORED-NAME",
                "tag": "IGNORED-TAG",
                "title": "IGNORED-TITLE",
            },
        )
    )
    entries: list[InputFile | InputSymlink] = [
        InputFile(primary_path, first_content, 0o640),
        InputFile(secondary_path, second_content, 0o444),
        InputFile("input/records/locked.jsonl", sentinel, 0o000),
        InputFile("input/records/wrong.jsonl.bak", sentinel, 0o644),
        InputSymlink("input/records/linked.jsonl", "locked.jsonl"),
    ]
    if profile.profile_id == "symlinks-ordering":
        entries.reverse()
    return tuple(entries)


def _parse_strict_json_object(line: bytes) -> dict[str, object] | None:
    if not line:
        return None
    try:
        text = line.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            parse_float=Decimal,
            parse_int=int,
            parse_constant=_reject_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        InvalidOperation,
        ValueError,
    ):
        return None
    return value if type(value) is dict else None


def _active_predicate_matches(
    record: dict[str, object], predicate: str
) -> bool:
    if predicate == "active-true":
        return record.get("active") is True
    if predicate == "enabled-yes":
        return record.get("enabled") == "yes"
    if predicate == "state-ready":
        return record.get("state") == "ready"
    if predicate == "deleted-false":
        return record.get("deleted") is False
    if predicate == "score-at-least-10":
        score = record.get("score")
        if type(score) is int:
            return score >= 10
        return (
            type(score) is Decimal
            and score.is_finite()
            and score >= Decimal(10)
        )
    raise ExecutableFixtureLineError("unsupported active JSON predicate")


def _active_expected_bytes(
    inputs: tuple[InputFile | InputSymlink, ...],
    parameters: ActiveJsonlLabelsParameters,
) -> bytes:
    labels: set[str] = set()
    for item in inputs:
        if type(item) is not InputFile:
            continue
        path = PurePosixPath(item.path)
        if not path.name.endswith(".jsonl") or not item.mode & 0o444:
            continue
        for raw_line in item.content.split(b"\n"):
            record = _parse_strict_json_object(raw_line)
            if record is None or not _active_predicate_matches(
                record, parameters.predicate
            ):
                continue
            label = record.get(parameters.label_key)
            if type(label) is not str or any(character in label for character in "\0\r\n"):
                continue
            try:
                label.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                continue
            labels.add(label)
    return b"".join(
        label.encode("utf-8") + b"\n"
        for label in sorted(labels, key=lambda value: value.encode("utf-8"))
    )


_PATH_COMPONENTS: Final[dict[str, tuple[tuple[str, ...], ...]]] = {
    "spaces-unicode": (
        ("root space",),
        ("dir space", "café file"),
        ("unicode", "雪", "third file"),
        ("four", "a b", "三", "deep file"),
        ("five", "a", "b", "c", "last name"),
    ),
    "leading-dashes-globs": (
        ("-root",),
        ("-dir", "[glob]*?"),
        ("three", "-nested", "[bracket]"),
        ("four", "a*", "b?", "-leaf"),
        ("five", "[x]", "a", "b", "*final?"),
    ),
    "empty-duplicates": (
        ("empty",),
        ("one", "repeat"),
        ("two", "nested", "repeat"),
        ("four", "a", "b", "repeat"),
        ("five", "a", "b", "c", "repeat"),
    ),
    "symlinks-ordering": (
        ("z-last",),
        ("a-first", "z-file"),
        ("middle", "a", "m-file"),
        ("beta", "z", "a", "file"),
        ("alpha", "z", "y", "x", "file"),
    ),
    "partial-permissions": (
        ("readable",),
        ("partial", "still-readable"),
        ("partial", "nested", "survivor"),
        ("partial", "a", "b", "deep-readable"),
        ("partial", "a", "b", "c", "last-readable"),
    ),
}


def _path_inputs(profile: ExecutableFixtureProfile) -> tuple[InputFile | InputSymlink, ...]:
    entries: list[InputFile | InputSymlink] = []
    components = _PATH_COMPONENTS[profile.profile_id]
    for suffix in _ALL_SUFFIXES:
        token = suffix.removeprefix(".")
        root_target: str | None = None
        for depth, stem_parts in enumerate(components, start=1):
            parts = (*stem_parts[:-1], stem_parts[-1] + suffix)
            relative = PurePosixPath(*parts)
            path = (PurePosixPath("input/tree") / relative).as_posix()
            content = (
                b""
                if profile.profile_id == "empty-duplicates" and depth == 1
                else f"{profile.profile_id}|{suffix}|depth={depth}\n".encode("utf-8")
            )
            entries.append(InputFile(path, content, 0o640 if depth % 2 else 0o444))
            if depth == 1:
                root_target = relative.name
        if root_target is None:  # pragma: no cover - frozen table invariant
            raise ExecutableFixtureLineError("path fixture lacks a root target")
        entries.extend(
            (
                InputFile(f"input/tree/locked-{token}{suffix}", b"unreadable\n", 0o000),
                InputFile(f"input/tree/wrong-{token}{suffix}.bak", b"wrong suffix\n", 0o644),
                InputSymlink(f"input/tree/link-{token}{suffix}", root_target),
            )
        )
    if profile.profile_id == "symlinks-ordering":
        entries.reverse()
    return tuple(entries)


def _path_expected_bytes(
    inputs: tuple[InputFile | InputSymlink, ...],
    parameters: PathSuffixInventoryParameters,
) -> bytes:
    selected: list[str] = []
    for item in inputs:
        if type(item) is not InputFile or not item.mode & 0o444:
            continue
        path = PurePosixPath(item.path)
        if path.parts[:2] != ("input", "tree"):
            raise ExecutableFixtureLineError("path input escaped input/tree")
        relative = PurePosixPath(*path.parts[2:])
        if not relative.name.endswith(parameters.suffix):
            continue
        if (
            parameters.maximum_depth != "unbounded"
            and len(relative.parts) > parameters.maximum_depth
        ):
            continue
        selected.append(relative.as_posix())
    selected.sort(key=lambda value: value.encode("utf-8"))
    return b"".join(path.encode("utf-8") + b"\n" for path in selected)


def _validate_task_and_profile(
    task: ExecutableStaticTask, profile: ExecutableFixtureProfile
) -> None:
    if type(task) is not ExecutableStaticTask:
        raise ExecutableFixtureLineError("task must be an exact ExecutableStaticTask")
    if type(profile) is not ExecutableFixtureProfile:
        raise ExecutableFixtureLineError(
            "profile must be an exact ExecutableFixtureProfile"
        )
    try:
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
        if reconstructed_profile not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
            raise ValueError("profile is not public method-development data")
        if task.family_id == "active-jsonl-labels":
            if type(task.parameters) is not ActiveJsonlLabelsParameters:
                raise ValueError("active task parameters have the wrong exact type")
            ActiveJsonlLabelsParameters(
                label_key=task.parameters.label_key,
                predicate=task.parameters.predicate,
            )
        elif task.family_id == "path-suffix-inventory":
            if type(task.parameters) is not PathSuffixInventoryParameters:
                raise ValueError("path task parameters have the wrong exact type")
            PathSuffixInventoryParameters(
                suffix=task.parameters.suffix,
                maximum_depth=task.parameters.maximum_depth,
            )
        else:
            raise ValueError("task family is not supported by the line generator")
        ExecutableStaticTask(
            task_id=task.task_id,
            family_id=task.family_id,
            family_version=task.family_version,
            parameters=task.parameters,
            prompt=task.prompt,
            graph=task.graph,
            filesystem_identity=task.filesystem_identity,
            output_identity=task.output_identity,
            allowed_tools=task.allowed_tools,
            fixtures=task.fixtures,
            task_contract_sha256=task.task_contract_sha256,
            split_role=task.split_role,
            public=task.public,
            sealed=task.sealed,
            claim_authorized=task.claim_authorized,
        )
    except (TypeError, ValueError) as exc:
        raise ExecutableFixtureLineError(
            "task/profile pair is outside the exact line-fixture contract"
        ) from exc


def build_executable_line_fixture_bundle(
    task: ExecutableStaticTask,
    profile: ExecutableFixtureProfile,
) -> ExecutableFixtureBundle:
    """Build one content-bound nonexecuting fixture for a supported line task."""

    _validate_task_and_profile(task, profile)
    fixture_id = f"fixture.{task.task_id}.{profile.profile_id}"
    if task.family_id == "active-jsonl-labels":
        parameters = task.parameters
        if type(parameters) is not ActiveJsonlLabelsParameters:  # pragma: no cover
            raise ExecutableFixtureLineError("active parameters changed after validation")
        inputs = _active_inputs(profile)
        output_path = _ACTIVE_OUTPUT
        expected_bytes = _active_expected_bytes(inputs, parameters)
        verifier = "verify-active-jsonl-labels-v1"
    elif task.family_id == "path-suffix-inventory":
        parameters = task.parameters
        if type(parameters) is not PathSuffixInventoryParameters:  # pragma: no cover
            raise ExecutableFixtureLineError("path parameters changed after validation")
        inputs = _path_inputs(profile)
        output_path = _PATH_OUTPUT
        expected_bytes = _path_expected_bytes(inputs, parameters)
        verifier = "verify-path-suffix-inventory-v1"
    else:  # pragma: no cover - validation rejects first
        raise ExecutableFixtureLineError("unsupported line fixture family")

    definition = FixtureDefinition(
        fixture_id=fixture_id,
        inputs=inputs,
        expected_files=(
            ExpectedFile(
                output_path,
                maximum_bytes=len(expected_bytes),
                mode=_OUTPUT_MODE,
            ),
        ),
    )
    oracle = build_trusted_fixture_oracle(
        (OracleOutputRecord(output_path, expected_bytes, _OUTPUT_MODE),),
        semantic_verifier_identity=verifier,
    )
    return build_executable_fixture_bundle(
        task_contract_sha256=task.task_contract_sha256,
        profile_sha256=profile.profile_sha256,
        definition=definition,
        oracle=oracle,
    )


__all__ = [
    "LINE_FIXTURE_GENERATOR_VERSION",
    "ExecutableFixtureLineError",
    "build_executable_line_fixture_bundle",
]
