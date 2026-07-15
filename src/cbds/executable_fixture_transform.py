"""Deterministic byte-transform mirror fixtures for method development.

The public task asks a candidate to recursively mirror readable regular files
whose basename has one selected suffix.  This module derives the private
oracle directly from immutable fixture bytes and metadata.  It never follows
fixture symlinks, decodes file content, or starts another process.
"""

from __future__ import annotations

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
    ExecutableStaticTask,
    LineTransformMirrorParameters,
)
from .executable_workspace import (
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
)


TRANSFORM_FIXTURE_GENERATOR_VERSION: Final[str] = "1.0.0"
OUTPUT_ROOT: Final[PurePosixPath] = PurePosixPath("output/mirror")
OUTPUT_MODE: Final[int] = 0o644
_ALL_SUFFIXES: Final[tuple[str, ...]] = (".txt", ".jsonl", ".log", ".csv")
_ASCII_LOWER_TABLE: Final[bytes] = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"abcdefghijklmnopqrstuvwxyz"
)
_ASCII_UPPER_TABLE: Final[bytes] = bytes.maketrans(
    b"abcdefghijklmnopqrstuvwxyz", b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
)


class ExecutableFixtureTransformError(ValueError):
    """Raised when a transform fixture is outside its closed contract."""


def _validate_task_profile(
    task: object, profile: object
) -> tuple[
    ExecutableStaticTask,
    ExecutableFixtureProfile,
    LineTransformMirrorParameters,
]:
    if (
        type(task) is not ExecutableStaticTask
        or task.family_id != "line-transform-mirror"
        or type(task.parameters) is not LineTransformMirrorParameters
    ):
        raise ExecutableFixtureTransformError(
            "task must be an exact line-transform-mirror ExecutableStaticTask"
        )
    if type(profile) is not ExecutableFixtureProfile:
        raise ExecutableFixtureTransformError(
            "profile must be an exact ExecutableFixtureProfile"
        )
    try:
        parameters = LineTransformMirrorParameters(
            suffix=task.parameters.suffix,
            transform=task.parameters.transform,
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
        raise ExecutableFixtureTransformError(
            "task or profile failed closed-contract revalidation"
        ) from exc
    if reconstructed_profile not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        raise ExecutableFixtureTransformError(
            "profile is not public method-development data"
        )
    return task, profile, parameters


def _mixed_content(profile_id: str, suffix: str, marker: str) -> bytes:
    """Return content with ASCII controls and bytes that are not valid UTF-8."""

    prefix = f"{profile_id}|{suffix}|{marker}|Az-aZ".encode("ascii")
    return prefix + b"\tcolumn\r\n" + "café|雪".encode("utf-8") + b"|\x00\xff\xc3(\n"


def _profile_regular_inputs(
    profile: ExecutableFixtureProfile,
    suffix: str,
) -> tuple[InputFile, ...]:
    token = suffix[1:]
    profile_id = profile.profile_id
    if profile_id == "spaces-unicode":
        return (
            InputFile(
                f"input/text/root space/{token} document{suffix}",
                _mixed_content(profile_id, suffix, "space"),
                0o640,
            ),
            InputFile(
                f"input/text/unicode 雪/café-{token}{suffix}",
                _mixed_content(profile_id, suffix, "unicode"),
                0o444,
            ),
        )
    if profile_id == "leading-dashes-globs":
        return (
            InputFile(
                f"input/text/-leading-{token}{suffix}",
                _mixed_content(profile_id, suffix, "dash"),
                0o604,
            ),
            InputFile(
                f"input/text/[glob]*?/{token}[x]*?{suffix}",
                _mixed_content(profile_id, suffix, "glob"),
                0o440,
            ),
        )
    if profile_id == "empty-duplicates":
        duplicate = b"duplicate\tAz-aZ\r\n\x00\xff"
        return (
            InputFile(f"input/text/empty-{token}{suffix}", b"", 0o400),
            InputFile(
                f"input/text/duplicate-a-{token}{suffix}", duplicate, 0o444
            ),
            InputFile(
                f"input/text/nested/duplicate-b-{token}{suffix}",
                duplicate,
                0o640,
            ),
        )
    if profile_id == "symlinks-ordering":
        return (
            InputFile(
                f"input/text/z-last-{token}{suffix}",
                _mixed_content(profile_id, suffix, "z-last"),
                0o444,
            ),
            InputFile(
                f"input/text/a-first/nested-{token}{suffix}",
                _mixed_content(profile_id, suffix, "a-first"),
                0o640,
            ),
        )
    if profile_id == "partial-permissions":
        return (
            InputFile(
                f"input/text/readable-{token}{suffix}",
                _mixed_content(profile_id, suffix, "readable"),
                0o404,
            ),
            InputFile(
                f"input/text/partial/nested-{token}{suffix}",
                _mixed_content(profile_id, suffix, "partial"),
                0o400,
            ),
        )
    raise ExecutableFixtureTransformError("unsupported fixture profile")


def _fixture_inputs(
    profile: ExecutableFixtureProfile,
) -> tuple[InputFile | InputSymlink, ...]:
    entries: list[InputFile | InputSymlink] = []
    for suffix in _ALL_SUFFIXES:
        token = suffix[1:]
        regulars = _profile_regular_inputs(profile, suffix)
        entries.extend(regulars)

        first = PurePosixPath(regulars[0].path)
        link_path = first.parent / f"link-{token}{suffix}"
        entries.extend(
            (
                # A matching but unreadable regular file must not be mirrored.
                InputFile(
                    f"input/text/unreadable-{token}{suffix}",
                    _mixed_content(profile.profile_id, suffix, "unreadable"),
                    0o000,
                ),
                # A matching file outside input/text must not be selected.
                InputFile(
                    f"input/outside/outside-{token}{suffix}",
                    _mixed_content(profile.profile_id, suffix, "outside"),
                    0o444,
                ),
                # A matching symlink must not be followed or mirrored.
                InputSymlink(link_path.as_posix(), first.name),
            )
        )
    if profile.profile_id == "symlinks-ordering":
        entries.reverse()
    return tuple(entries)


def _transform_bytes(content: bytes, transform: str) -> bytes:
    if transform == "identity":
        return content
    if transform == "ascii-upper":
        return content.translate(_ASCII_UPPER_TABLE)
    if transform == "ascii-lower":
        return content.translate(_ASCII_LOWER_TABLE)
    if transform == "tabs-to-four-spaces":
        return content.replace(b"\t", b"    ")
    if transform == "delete-carriage-returns":
        return content.replace(b"\r", b"")
    raise ExecutableFixtureTransformError("unsupported byte transform")


def _derive_outputs(
    inputs: tuple[InputFile | InputSymlink, ...],
    parameters: LineTransformMirrorParameters,
) -> tuple[OracleOutputRecord, ...]:
    outputs: list[OracleOutputRecord] = []
    for item in inputs:
        if type(item) is not InputFile or item.mode & 0o444 == 0:
            continue
        path = PurePosixPath(item.path)
        if path.parts[:2] != ("input", "text"):
            continue
        relative = PurePosixPath(*path.parts[2:])
        if not relative.name.endswith(parameters.suffix):
            continue
        output_path = (OUTPUT_ROOT / relative).as_posix()
        outputs.append(
            OracleOutputRecord(
                output_path,
                _transform_bytes(item.content, parameters.transform),
                OUTPUT_MODE,
            )
        )
    outputs.sort(key=lambda output: output.path.encode("utf-8"))
    if not outputs:
        raise ExecutableFixtureTransformError(
            "fixture must contain at least one selected readable regular file"
        )
    return tuple(outputs)


def build_line_transform_mirror_fixture_bundle(
    task: ExecutableStaticTask,
    profile: ExecutableFixtureProfile,
) -> ExecutableFixtureBundle:
    """Build one nonexecuting content-bound byte-transform fixture bundle."""

    task, profile, parameters = _validate_task_profile(task, profile)
    inputs = _fixture_inputs(profile)
    outputs = _derive_outputs(inputs, parameters)
    definition = FixtureDefinition(
        fixture_id=f"dev.line-transform-mirror.{profile.profile_id}",
        inputs=inputs,
        expected_files=tuple(
            ExpectedFile(
                output.path,
                maximum_bytes=len(output.content),
                mode=OUTPUT_MODE,
            )
            for output in outputs
        ),
    )
    oracle = build_trusted_fixture_oracle(
        outputs,
        semantic_verifier_identity="verify-line-transform-mirror-v1",
    )
    return build_executable_fixture_bundle(
        task_contract_sha256=task.task_contract_sha256,
        profile_sha256=profile.profile_sha256,
        definition=definition,
        oracle=oracle,
    )


__all__ = [
    "TRANSFORM_FIXTURE_GENERATOR_VERSION",
    "ExecutableFixtureTransformError",
    "build_line_transform_mirror_fixture_bundle",
]
