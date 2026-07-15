"""Deterministic mode-normalized mirror fixtures for method development.

The public task selects mode-readable regular files below ``input/assets``
without following symlinks, copies their bytes exactly, and assigns modes by
one closed normalization rule.  This private builder derives that answer from
immutable fixture metadata only.  It never inspects the host filesystem,
decodes file content, or starts another process.
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
    ModeNormalizedMirrorParameters,
)
from .executable_workspace import (
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
)


MODE_MIRROR_FIXTURE_GENERATOR_VERSION: Final[str] = "1.0.0"
OUTPUT_ROOT: Final[PurePosixPath] = PurePosixPath("output/mirror")
_READ_BITS: Final[int] = 0o444
_EXECUTE_BITS: Final[int] = 0o111
_OWNER_WRITE_BIT: Final[int] = 0o200


class ExecutableFixtureModeMirrorError(ValueError):
    """Raised when a mode-mirror fixture is outside its closed contract."""


def _validate_task_profile(
    task: object, profile: object
) -> tuple[
    ExecutableStaticTask,
    ExecutableFixtureProfile,
    ModeNormalizedMirrorParameters,
]:
    if (
        type(task) is not ExecutableStaticTask
        or task.family_id != "mode-normalized-mirror"
        or type(task.parameters) is not ModeNormalizedMirrorParameters
    ):
        raise ExecutableFixtureModeMirrorError(
            "task must be an exact mode-normalized-mirror ExecutableStaticTask"
        )
    if type(profile) is not ExecutableFixtureProfile:
        raise ExecutableFixtureModeMirrorError(
            "profile must be an exact ExecutableFixtureProfile"
        )
    try:
        parameters = ModeNormalizedMirrorParameters(
            selector=task.parameters.selector,
            normalization=task.parameters.normalization,
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
        raise ExecutableFixtureModeMirrorError(
            "task or profile failed closed-contract revalidation"
        ) from exc
    if reconstructed_profile not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        raise ExecutableFixtureModeMirrorError(
            "profile is not public method-development data"
        )
    return task, profile, parameters


def _content(profile_id: str, marker: str) -> bytes:
    """Return exact-copy test bytes, including NUL and invalid UTF-8."""

    return (
        f"{profile_id}|{marker}|Az-aZ|".encode("utf-8")
        + "café|雪|".encode("utf-8")
        + b"\x00\xff\t\r\n"
    )


def _fixture_inputs(
    profile: ExecutableFixtureProfile,
) -> tuple[InputFile | InputSymlink, ...]:
    profile_id = profile.profile_id
    entries: tuple[InputFile | InputSymlink, ...]
    if profile_id == "spaces-unicode":
        entries = (
            InputFile(
                "input/assets/root space/read me.txt",
                _content(profile_id, "space-owner-writable"),
                0o640,
            ),
            InputFile(
                "input/assets/unicode 雪/café-run.bin",
                _content(profile_id, "unicode-group-executable"),
                0o450,
            ),
            InputFile(
                "input/assets/unicode 雪/owner-private.data",
                _content(profile_id, "owner-private"),
                0o600,
            ),
            InputFile(
                "input/assets/root space/unreadable.txt",
                _content(profile_id, "unreadable"),
                0o200,
            ),
            InputSymlink(
                "input/assets/root space/read-link.txt",
                "read me.txt",
            ),
            InputFile(
                "input/outside/outside.txt",
                _content(profile_id, "outside"),
                0o777,
            ),
        )
    elif profile_id == "leading-dashes-globs":
        entries = (
            InputFile(
                "input/assets/-leading.txt",
                _content(profile_id, "leading-dash"),
                0o404,
            ),
            InputFile(
                "input/assets/[glob]*?/script?[x].bin",
                _content(profile_id, "owner-executable"),
                0o540,
            ),
            InputFile(
                "input/assets/[glob]*?/writable[*].data",
                _content(profile_id, "owner-write-group-read"),
                0o640,
            ),
            InputFile(
                "input/assets/[glob]*?/execute-only.txt",
                _content(profile_id, "execute-without-read"),
                0o311,
            ),
            InputSymlink(
                "input/assets/[glob]*?/link*.txt",
                "writable[*].data",
            ),
            InputFile(
                "input/outside/[glob]-outside.txt",
                _content(profile_id, "outside"),
                0o755,
            ),
        )
    elif profile_id == "empty-duplicates":
        duplicate = b"same exact bytes\x00\xff\n"
        entries = (
            InputFile("input/assets/empty.txt", b"", 0o600),
            InputFile("input/assets/duplicate-a.bin", duplicate, 0o405),
            InputFile(
                "input/assets/nested/duplicate-b.data",
                duplicate,
                0o640,
            ),
            InputFile(
                "input/assets/unreadable-empty.txt",
                b"",
                0o000,
            ),
            InputSymlink(
                "input/assets/duplicate-link.txt",
                "duplicate-a.bin",
            ),
            InputFile(
                "input/outside/duplicate.txt",
                duplicate,
                0o777,
            ),
        )
    elif profile_id == "symlinks-ordering":
        # Deliberately reverse the byte-sort order to make discovery order
        # observable in the private definition while the oracle stays sorted.
        entries = (
            InputFile(
                "input/outside/out-of-root.txt",
                _content(profile_id, "outside"),
                0o777,
            ),
            InputFile(
                "input/assets/z-last.txt",
                _content(profile_id, "z-last"),
                0o444,
            ),
            InputFile(
                "input/assets/middle/write.data",
                _content(profile_id, "owner-write-other-read"),
                0o604,
            ),
            InputSymlink(
                "input/assets/link-first.txt",
                "z-last.txt",
            ),
            InputFile(
                "input/assets/a-first/nested-run.bin",
                _content(profile_id, "group-executable"),
                0o410,
            ),
            InputFile(
                "input/assets/a-first/unreadable.txt",
                _content(profile_id, "unreadable"),
                0o000,
            ),
        )
    elif profile_id == "partial-permissions":
        entries = (
            InputFile(
                "input/assets/owner-read.txt",
                _content(profile_id, "owner-read"),
                0o400,
            ),
            InputFile(
                "input/assets/group-read-exec.bin",
                _content(profile_id, "group-read-exec"),
                0o450,
            ),
            InputFile(
                "input/assets/owner-write-other-read.data",
                _content(profile_id, "owner-write-other-read"),
                0o604,
            ),
            InputFile(
                "input/assets/other-read-exec.bin",
                _content(profile_id, "other-read-exec"),
                0o405,
            ),
            InputFile(
                "input/assets/group-read-only.data",
                _content(profile_id, "group-read"),
                0o440,
            ),
            InputFile(
                "input/assets/unreadable.txt",
                _content(profile_id, "unreadable"),
                0o000,
            ),
            InputFile(
                "input/assets/write-exec-no-read.bin",
                _content(profile_id, "write-exec-no-read"),
                0o311,
            ),
            InputSymlink(
                "input/assets/owner-read-link.txt",
                "owner-read.txt",
            ),
            InputFile(
                "input/outside/permission-decoy.txt",
                _content(profile_id, "outside"),
                0o777,
            ),
        )
    else:
        raise ExecutableFixtureModeMirrorError("unsupported fixture profile")
    return entries


def _is_selected(item: InputFile, selector: str) -> bool:
    if item.mode & _READ_BITS == 0:
        return False
    if selector == "all-readable":
        return True
    if selector == "txt-suffix":
        return PurePosixPath(item.path).name.endswith(".txt")
    if selector == "any-executable":
        return item.mode & _EXECUTE_BITS != 0
    if selector == "owner-writable":
        return item.mode & _OWNER_WRITE_BIT != 0
    raise ExecutableFixtureModeMirrorError("unsupported mode-mirror selector")


def _normalized_mode(source_mode: int, normalization: str) -> int:
    if normalization == "fixed-0644":
        return 0o644
    if normalization == "fixed-0600":
        return 0o600
    if normalization == "fixed-0444":
        return 0o444
    if normalization == "preserve-exec":
        return 0o755 if source_mode & _EXECUTE_BITS else 0o644
    if normalization == "fold-class-bits-to-owner":
        return (
            ((source_mode >> 6) | (source_mode >> 3) | source_mode) & 0o7
        ) << 6
    raise ExecutableFixtureModeMirrorError("unsupported mode normalization")


def _derive_outputs(
    inputs: tuple[InputFile | InputSymlink, ...],
    parameters: ModeNormalizedMirrorParameters,
) -> tuple[OracleOutputRecord, ...]:
    outputs: list[OracleOutputRecord] = []
    for item in inputs:
        if type(item) is not InputFile:
            continue
        path = PurePosixPath(item.path)
        if path.parts[:2] != ("input", "assets"):
            continue
        if not _is_selected(item, parameters.selector):
            continue
        relative = PurePosixPath(*path.parts[2:])
        outputs.append(
            OracleOutputRecord(
                (OUTPUT_ROOT / relative).as_posix(),
                item.content,
                _normalized_mode(item.mode, parameters.normalization),
            )
        )
    outputs.sort(key=lambda output: output.path.encode("utf-8"))
    if not outputs:
        raise ExecutableFixtureModeMirrorError(
            "fixture must contain at least one selected mode-readable regular file"
        )
    return tuple(outputs)


def build_mode_normalized_mirror_fixture_bundle(
    task: ExecutableStaticTask,
    profile: ExecutableFixtureProfile,
) -> ExecutableFixtureBundle:
    """Build one nonexecuting, content-bound mode-normalized mirror bundle."""

    task, profile, parameters = _validate_task_profile(task, profile)
    inputs = _fixture_inputs(profile)
    outputs = _derive_outputs(inputs, parameters)
    definition = FixtureDefinition(
        fixture_id=f"dev.mode-normalized-mirror.{profile.profile_id}",
        inputs=inputs,
        expected_files=tuple(
            ExpectedFile(
                output.path,
                maximum_bytes=len(output.content),
                mode=output.mode,
            )
            for output in outputs
        ),
    )
    oracle = build_trusted_fixture_oracle(
        outputs,
        semantic_verifier_identity="verify-mode-normalized-mirror-v1",
    )
    return build_executable_fixture_bundle(
        task_contract_sha256=task.task_contract_sha256,
        profile_sha256=profile.profile_sha256,
        definition=definition,
        oracle=oracle,
    )


__all__ = [
    "MODE_MIRROR_FIXTURE_GENERATOR_VERSION",
    "ExecutableFixtureModeMirrorError",
    "build_mode_normalized_mirror_fixture_bundle",
]
