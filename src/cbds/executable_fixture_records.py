"""Deterministic manifest-copy and checksum-manifest development fixtures.

The generators in this module construct trusted inputs and reference outputs;
they never execute candidate code.  Reference results are derived by parsing
the generated manifest bytes through the family contract, then bound into an
opaque :class:`~cbds.executable_static_types.OpaqueFixtureDescriptor`.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
import csv
from hashlib import sha256
import io
import json
from pathlib import PurePosixPath
import re
from typing import Any, Final

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
    ChecksumManifestParameters,
    ExecutableStaticTask,
    ManifestCopyParameters,
)
from .executable_workspace import (
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
)


OUTPUT_MODE: Final[int] = 0o644
OUTPUT_LIMIT: Final[int] = 256 * 1024
_LOWER_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_MODE_RE: Final[re.Pattern[str]] = re.compile(r"[0-7]{3}\Z")


class ExecutableFixtureRecordError(ValueError):
    """Raised when a record-family fixture cannot be derived exactly."""


def _strict_json(text: str) -> object:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number: {value}")

    return json.loads(
        text,
        parse_constant=reject_constant,
    )


def _json_line(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _jsonl(values: Iterable[object], *, malformed: tuple[str, ...] = ()) -> bytes:
    lines = [_json_line(value) for value in values]
    lines.extend(malformed)
    return (("\n".join(lines) + "\n") if lines else "").encode("utf-8")


def _safe_relative(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return None
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        return None
    return value


def _validate_task_and_profile(
    task: object,
    profile: object,
    *,
    family_id: str,
    parameter_type: type[object],
) -> tuple[ExecutableStaticTask, ExecutableFixtureProfile]:
    if type(task) is not ExecutableStaticTask or task.family_id != family_id:
        raise ExecutableFixtureRecordError(
            f"task must be an exact {family_id} ExecutableStaticTask"
        )
    if type(task.parameters) is not parameter_type:
        raise ExecutableFixtureRecordError("task parameters do not match family")
    if type(profile) is not ExecutableFixtureProfile:
        raise ExecutableFixtureRecordError(
            "profile must be an exact ExecutableFixtureProfile"
        )
    try:
        task.__post_init__()
        profile.__post_init__()
    except (TypeError, ValueError) as exc:
        raise ExecutableFixtureRecordError(
            "task or profile failed closed-contract revalidation"
        ) from exc
    if profile not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        raise ExecutableFixtureRecordError(
            "profile is not public method-development data"
        )
    return task, profile


def _profile_names(profile: ExecutableFixtureProfile) -> tuple[str, str, bytes, bytes]:
    values: dict[str, tuple[str, str, bytes, bytes]] = {
        "spaces-unicode": (
            "space name.txt",
            "한글 자료.bin",
            b"space payload\n",
            "유니코드 payload\n".encode("utf-8"),
        ),
        "leading-dashes-globs": (
            "-leading.txt",
            "glob[*]?.dat",
            b"leading dash\n",
            b"literal glob\n",
        ),
        "empty-duplicates": (
            "empty.txt",
            "same-bytes.dat",
            b"",
            b"same bytes\n",
        ),
        "symlinks-ordering": (
            "z-last.txt",
            "a-first.dat",
            b"z payload\n",
            b"a payload\n",
        ),
        "partial-permissions": (
            "readable.txt",
            "partial.dat",
            b"readable\n",
            b"partial\n",
        ),
    }
    try:
        return values[profile.profile_id]
    except KeyError as exc:  # closed profile type is also checked above
        raise ExecutableFixtureRecordError("unsupported fixture profile") from exc


def _copy_inputs(
    profile: ExecutableFixtureProfile,
) -> tuple[tuple[InputFile | InputSymlink, ...], bytes]:
    first_name, second_name, first_bytes, second_bytes = _profile_names(profile)
    identical_name = "identical-copy.txt"
    unreadable_name = "unreadable.txt"
    collision_sources = (
        ("z-choice.txt", b"z collision choice\n"),
        ("a-choice.txt", b"a collision choice\n"),
        ("m-choice.txt", b"m collision choice\n"),
    )
    inputs: tuple[InputFile | InputSymlink, ...] = (
        InputFile(f"input/files/{first_name}", first_bytes),
        InputFile(f"input/files/{second_name}", second_bytes),
        InputFile(f"input/files/{identical_name}", first_bytes),
        *(InputFile(f"input/files/{name}", content) for name, content in collision_sources),
        InputFile(f"input/files/{unreadable_name}", b"must not copy\n", 0o000),
        InputSymlink("input/files/link-source.txt", first_name),
    )
    first_digest = sha256(first_bytes).hexdigest()
    second_digest = sha256(second_bytes).hexdigest()
    records: list[object] = [
        *(
            {
                "source": name,
                "destination": "shared/result.txt",
                "selected": True,
                "sha256": sha256(content).hexdigest(),
            }
            for name, content in collision_sources
        ),
        {
            "source": first_name,
            "destination": "unique/universal.txt",
            "selected": True,
            "sha256": first_digest,
        },
        {
            "source": second_name,
            "destination": "unique/all-readable-only.bin",
            "selected": False,
            "sha256": "0" * 64,
        },
        {
            "source": first_name,
            "destination": "unique/txt-only.txt",
            "selected": False,
            "sha256": "0" * 64,
        },
        {
            "source": second_name,
            "destination": "unique/selected-only.bin",
            "selected": True,
            "sha256": "0" * 64,
        },
        {
            "source": second_name,
            "destination": "unique/digest-only.bin",
            "selected": False,
            "sha256": second_digest,
        },
        {
            "source": first_name,
            "destination": "identical/result.txt",
            "selected": True,
            "sha256": first_digest,
        },
        {
            "source": identical_name,
            "destination": "identical/result.txt",
            "selected": True,
            "sha256": first_digest,
        },
        {
            "source": unreadable_name,
            "destination": "ignored/unreadable.txt",
            "selected": True,
            "sha256": sha256(b"must not copy\n").hexdigest(),
        },
        {
            "source": "link-source.txt",
            "destination": "ignored/symlink.txt",
            "selected": True,
            "sha256": first_digest,
        },
        {
            "source": "missing.txt",
            "destination": "ignored/missing.txt",
            "selected": True,
            "sha256": "0" * 64,
        },
        {"source": "../escape", "destination": "ignored/unsafe.txt"},
        {"source": first_name, "destination": "/absolute"},
        {"source": 3, "destination": "ignored/type.txt"},
    ]
    if profile.profile_id == "empty-duplicates":
        records.insert(1, dict(records[0]))
    if profile.profile_id == "symlinks-ordering":
        records = list(reversed(records))
    manifest = _jsonl(records, malformed=("{malformed-json", "[]"))
    return (*inputs, InputFile("input/copy-map.jsonl", manifest)), manifest


def _copy_source_table(
    inputs: tuple[InputFile | InputSymlink, ...],
) -> dict[str, InputFile | InputSymlink]:
    prefix = "input/files/"
    return {
        item.path.removeprefix(prefix): item
        for item in inputs
        if item.path.startswith(prefix)
    }


def _parse_copy_records(manifest: bytes) -> tuple[dict[str, Any], ...]:
    try:
        text = manifest.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ExecutableFixtureRecordError("generated copy manifest is not UTF-8") from exc
    accepted: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line:
            continue
        try:
            value = _strict_json(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(value, dict):
            continue
        source = _safe_relative(value.get("source"))
        destination = _safe_relative(value.get("destination"))
        if source is None or destination is None:
            continue
        accepted.append({**value, "source": source, "destination": destination})
    return tuple(accepted)


def _derive_copy_outputs(
    inputs: tuple[InputFile | InputSymlink, ...],
    manifest: bytes,
    parameters: ManifestCopyParameters,
) -> tuple[OracleOutputRecord, ...]:
    sources = _copy_source_table(inputs)
    eligible: list[tuple[int, str, str, bytes]] = []
    for ordinal, record in enumerate(_parse_copy_records(manifest)):
        source_path = str(record["source"])
        source = sources.get(source_path)
        if type(source) is not InputFile or source.mode & 0o444 == 0:
            continue
        if parameters.selector == "txt-suffix" and not PurePosixPath(
            source_path
        ).name.endswith(".txt"):
            continue
        if parameters.selector == "selected-true" and record.get("selected") is not True:
            continue
        if parameters.selector == "declared-sha256-matches":
            declared = record.get("sha256")
            if (
                not isinstance(declared, str)
                or _LOWER_SHA256_RE.fullmatch(declared) is None
                or declared != sha256(source.content).hexdigest()
            ):
                continue
        eligible.append(
            (ordinal, source_path, str(record["destination"]), source.content)
        )

    groups: dict[str, list[tuple[int, str, str, bytes]]] = defaultdict(list)
    for item in eligible:
        groups[item[2]].append(item)
    outputs: list[OracleOutputRecord] = []
    for destination, candidates in groups.items():
        chosen: tuple[int, str, str, bytes] | None
        if len(candidates) == 1:
            chosen = candidates[0]
        elif parameters.collision_policy == "reject-collision":
            chosen = None
        elif parameters.collision_policy == "first-record":
            chosen = min(candidates, key=lambda item: item[0])
        elif parameters.collision_policy == "last-record":
            chosen = max(candidates, key=lambda item: item[0])
        elif parameters.collision_policy == "identical-bytes-only":
            chosen = candidates[0] if len({item[3] for item in candidates}) == 1 else None
        elif parameters.collision_policy == "utf8-smallest-source":
            chosen = min(candidates, key=lambda item: item[1].encode("utf-8"))
        else:  # closed parameter class makes this unreachable without tampering
            raise ExecutableFixtureRecordError("unsupported collision policy")
        if chosen is not None:
            outputs.append(
                OracleOutputRecord(
                    path=f"output/{destination}",
                    content=chosen[3],
                    mode=OUTPUT_MODE,
                )
            )
    return tuple(sorted(outputs, key=lambda item: item.path.encode("utf-8")))


def build_manifest_copy_fixture_bundle(
    task: ExecutableStaticTask,
    profile: ExecutableFixtureProfile,
) -> ExecutableFixtureBundle:
    task, profile = _validate_task_and_profile(
        task,
        profile,
        family_id="manifest-copy",
        parameter_type=ManifestCopyParameters,
    )
    inputs, manifest = _copy_inputs(profile)
    outputs = _derive_copy_outputs(inputs, manifest, task.parameters)
    definition = FixtureDefinition(
        fixture_id=f"dev.manifest-copy.{profile.profile_id}",
        inputs=inputs,
        expected_files=tuple(
            ExpectedFile(item.path, maximum_bytes=OUTPUT_LIMIT, mode=OUTPUT_MODE)
            for item in outputs
        ),
    )
    oracle = build_trusted_fixture_oracle(
        outputs,
        semantic_verifier_identity="verify-manifest-copy-tree-v1",
    )
    return build_executable_fixture_bundle(
        task_contract_sha256=task.task_contract_sha256,
        profile_sha256=profile.profile_sha256,
        definition=definition,
        oracle=oracle,
    )


def _asset_inputs(
    profile: ExecutableFixtureProfile,
) -> tuple[InputFile | InputSymlink, ...]:
    first_name, second_name, first_bytes, second_bytes = _profile_names(profile)
    return (
        InputFile(f"input/assets/{first_name}", first_bytes, 0o640),
        InputFile(f"input/assets/{second_name}", second_bytes, 0o600),
        InputFile('input/assets/quoted,"asset".bin', b"quoted asset bytes\n", 0o644),
        InputFile("input/assets/unreadable.bin", b"unreadable bytes\n", 0o000),
        InputFile("input/assets/directory/child.txt", b"directory marker\n", 0o644),
        InputSymlink("input/assets/link-to-first", first_name),
    )


def _checksum_records(
    profile: ExecutableFixtureProfile,
    assets: tuple[InputFile | InputSymlink, ...],
) -> tuple[tuple[str, str, str], ...]:
    first_name, second_name, _first_bytes, _second_bytes = _profile_names(profile)
    table = {
        item.path.removeprefix("input/assets/"): item
        for item in assets
        if type(item) is InputFile
    }
    first = table[first_name]
    second = table[second_name]
    unreadable = table["unreadable.bin"]
    quoted = table['quoted,"asset".bin']
    if any(type(item) is not InputFile for item in (first, second, unreadable, quoted)):
        raise ExecutableFixtureRecordError("generated checksum asset table is invalid")
    records: list[tuple[str, str, str]] = [
        (first_name, sha256(first.content).hexdigest(), f"{first.mode:03o}"),
        (second_name, "0" * 64, "644"),
        (second_name, sha256(second.content).hexdigest(), "644"),
        (
            'quoted,"asset".bin',
            sha256(quoted.content).hexdigest(),
            f"{quoted.mode:03o}",
        ),
        (
            "unreadable.bin",
            sha256(unreadable.content).hexdigest(),
            "000",
        ),
        ("missing.file", "1" * 64, "644"),
        ("directory", "2" * 64, "755"),
        ("link-to-first", sha256(first.content).hexdigest(), f"{first.mode:03o}"),
        (first_name, "f" * 64, f"{first.mode:03o}"),
    ]
    if profile.profile_id == "empty-duplicates":
        records.insert(1, records[0])
    if profile.profile_id == "symlinks-ordering":
        records = list(reversed(records))
    return tuple(records)


def _encode_checksum_manifest(
    records: tuple[tuple[str, str, str], ...],
    layout: str,
) -> bytes:
    if layout == "json-object-lines":
        return _jsonl(
            (
                {"path": path, "sha256": digest, "mode": mode}
                for path, digest, mode in records
            ),
            malformed=("{not-json", _json_line({"path": 3})),
        )
    if layout == "json-array-lines":
        return _jsonl(
            ([path, digest, mode] for path, digest, mode in records),
            malformed=(_json_line(["too", "short"]), "[not-json"),
        )
    if layout == "rfc4180-csv":
        stream = io.StringIO(newline="")
        writer = csv.writer(stream, lineterminator="\r\n")
        writer.writerow(("path", "sha256", "mode"))
        writer.writerows(records)
        writer.writerow(("malformed", "row"))
        return stream.getvalue().encode("utf-8")
    if layout == "nul-triplets":
        payload = bytearray()
        for record in records:
            for field in record:
                payload.extend(field.encode("utf-8"))
                payload.append(0)
        payload.extend(b"incomplete\x00record\x00")
        return bytes(payload)
    raise ExecutableFixtureRecordError("unsupported checksum manifest layout")


def _valid_checksum_record(
    path: object, digest: object, mode: object
) -> tuple[str, str, str] | None:
    safe_path = _safe_relative(path)
    if (
        safe_path is None
        or not isinstance(digest, str)
        or _LOWER_SHA256_RE.fullmatch(digest) is None
        or not isinstance(mode, str)
        or _MODE_RE.fullmatch(mode) is None
    ):
        return None
    return safe_path, digest, mode


def _parse_checksum_manifest(
    payload: bytes, layout: str
) -> tuple[tuple[str, str, str], ...]:
    accepted: list[tuple[str, str, str]] = []
    if layout in {"json-object-lines", "json-array-lines"}:
        try:
            lines = payload.decode("utf-8", errors="strict").splitlines()
        except UnicodeDecodeError:
            return ()
        for line in lines:
            if not line:
                continue
            try:
                value = _strict_json(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if layout == "json-object-lines":
                if not isinstance(value, dict) or set(value) != {"path", "sha256", "mode"}:
                    continue
                candidate = _valid_checksum_record(
                    value["path"], value["sha256"], value["mode"]
                )
            else:
                if not isinstance(value, list) or len(value) != 3:
                    continue
                candidate = _valid_checksum_record(*value)
            if candidate is not None:
                accepted.append(candidate)
        return tuple(accepted)
    if layout == "rfc4180-csv":
        try:
            text = payload.decode("utf-8", errors="strict")
            rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
        except (UnicodeDecodeError, csv.Error):
            return ()
        if not rows or rows[0] != ["path", "sha256", "mode"]:
            return ()
        for row in rows[1:]:
            candidate = _valid_checksum_record(*row) if len(row) == 3 else None
            if candidate is not None:
                accepted.append(candidate)
        return tuple(accepted)
    if layout == "nul-triplets":
        fields = payload.split(b"\0")
        if fields and fields[-1] == b"":
            fields.pop()
        for index in range(0, len(fields) - 2, 3):
            try:
                values = tuple(
                    field.decode("utf-8", errors="strict")
                    for field in fields[index : index + 3]
                )
            except UnicodeDecodeError:
                continue
            candidate = _valid_checksum_record(*values)
            if candidate is not None:
                accepted.append(candidate)
        return tuple(accepted)
    raise ExecutableFixtureRecordError("unsupported checksum manifest layout")


def _checksum_status(
    record: tuple[str, str, str],
    *,
    policy: str,
    assets: tuple[InputFile | InputSymlink, ...],
) -> str:
    path, expected_digest, expected_mode = record
    prefix = "input/assets/"
    entries = {
        item.path.removeprefix(prefix): item
        for item in assets
        if item.path.startswith(prefix)
    }
    directories: set[str] = set()
    for item in assets:
        if not item.path.startswith(prefix):
            continue
        relative = PurePosixPath(item.path.removeprefix(prefix))
        directories.update(
            parent.as_posix()
            for parent in relative.parents
            if parent != PurePosixPath(".")
        )
    entry = entries.get(path)
    kind: str
    if entry is None and path in directories:
        kind = "directory"
    elif entry is None:
        kind = "missing"
    elif type(entry) is InputSymlink:
        kind = "symlink"
    elif type(entry) is InputFile:
        kind = "regular"
    else:  # pragma: no cover - closed workspace input types
        raise ExecutableFixtureRecordError("unsupported checksum asset kind")

    if policy == "strict-kind-digest-and-mode":
        if kind in {"missing", "symlink", "directory"}:
            return kind
    elif policy == "readable-digest-and-mode":
        if kind == "missing":
            return "missing"
        if kind != "regular":
            return "not_regular"
    elif kind != "regular":
        return "unavailable"

    if type(entry) is not InputFile:
        raise ExecutableFixtureRecordError("regular checksum entry is malformed")
    readable = entry.mode & 0o444 != 0
    if policy != "mode-only" and not readable:
        return "unreadable" if policy in {
            "readable-digest-and-mode",
            "strict-kind-digest-and-mode",
        } else "unavailable"

    mode_matches = f"{entry.mode:03o}" == expected_mode
    if policy == "mode-only":
        return "ok" if mode_matches else "mode_mismatch"
    digest_matches = sha256(entry.content).hexdigest() == expected_digest
    if policy == "digest-only":
        return "ok" if digest_matches else "checksum_mismatch"
    if digest_matches and mode_matches:
        return "ok"
    if not digest_matches and not mode_matches:
        return "checksum_and_mode_mismatch"
    return "checksum_mismatch" if not digest_matches else "mode_mismatch"


def _derive_checksum_output(
    assets: tuple[InputFile | InputSymlink, ...],
    manifest: bytes,
    parameters: ChecksumManifestParameters,
) -> bytes:
    records = _parse_checksum_manifest(manifest, parameters.layout)
    indexed = [
        (
            ordinal,
            path,
            _checksum_status(record, policy=parameters.policy, assets=assets),
        )
        for ordinal, record in enumerate(records)
        for path in (record[0],)
    ]
    indexed.sort(key=lambda item: (item[1].encode("utf-8"), item[0]))
    return (
        "".join(
            _json_line({"path": path, "status": status}) + "\n"
            for _ordinal, path, status in indexed
        )
    ).encode("utf-8")


def build_checksum_manifest_fixture_bundle(
    task: ExecutableStaticTask,
    profile: ExecutableFixtureProfile,
) -> ExecutableFixtureBundle:
    task, profile = _validate_task_and_profile(
        task,
        profile,
        family_id="checksum-manifest",
        parameter_type=ChecksumManifestParameters,
    )
    assets = _asset_inputs(profile)
    records = _checksum_records(profile, assets)
    manifest = _encode_checksum_manifest(records, task.parameters.layout)
    inputs = (*assets, InputFile("input/manifest.data", manifest))
    content = _derive_checksum_output(assets, manifest, task.parameters)
    output = OracleOutputRecord(
        path="output/report.jsonl",
        content=content,
        mode=OUTPUT_MODE,
    )
    definition = FixtureDefinition(
        fixture_id=f"dev.checksum-manifest.{profile.profile_id}",
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
        semantic_verifier_identity="verify-checksum-manifest-v1",
    )
    return build_executable_fixture_bundle(
        task_contract_sha256=task.task_contract_sha256,
        profile_sha256=profile.profile_sha256,
        definition=definition,
        oracle=oracle,
    )


__all__ = [
    "ExecutableFixtureRecordError",
    "build_checksum_manifest_fixture_bundle",
    "build_manifest_copy_fixture_bundle",
]
