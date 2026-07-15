from __future__ import annotations

from collections import defaultdict
import csv
from hashlib import sha256
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)
from cbds.executable_fixture_records import (  # noqa: E402
    build_checksum_manifest_fixture_bundle,
    build_manifest_copy_fixture_bundle,
)
from cbds.executable_static_registry import (  # noqa: E402
    build_public_method_development_registry,
)
from cbds.executable_workspace import InputFile, InputSymlink  # noqa: E402


_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_OCTAL_MODE = re.compile(r"[0-7]{3}\Z")
_OUTPUT_MODE = 0o644


REGISTRY = build_public_method_development_registry()
RECORD_TASKS = tuple(
    task
    for task in REGISTRY.tasks
    if task.family_id in {"manifest-copy", "checksum-manifest"}
)


def _strict_json(text: str) -> object:
    """Parse JSON without accepting duplicate keys or non-finite numbers."""

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON value: {value}")

    def reject_duplicate_keys(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(
        text,
        parse_constant=reject_constant,
        object_pairs_hook=reject_duplicate_keys,
    )


def _safe_relative_path(value: object) -> str | None:
    if type(value) is not str or not value:
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


def _only_regular_input(definition: object, path: str) -> InputFile:
    matches = tuple(
        entry
        for entry in definition.inputs
        if getattr(entry, "path", None) == path
    )
    if len(matches) != 1 or type(matches[0]) is not InputFile:
        raise AssertionError(f"fixture does not contain one regular input at {path}")
    return matches[0]


def _parse_copy_manifest(payload: bytes) -> tuple[dict[str, object], ...]:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return ()
    records: list[dict[str, object]] = []
    for line in text.splitlines():
        if not line:
            continue
        try:
            value = _strict_json(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if type(value) is not dict:
            continue
        source = _safe_relative_path(value.get("source"))
        destination = _safe_relative_path(value.get("destination"))
        if source is None or destination is None:
            continue
        record = dict(value)
        record["source"] = source
        record["destination"] = destination
        records.append(record)
    return tuple(records)


def _reference_manifest_outputs(
    bundle: object,
    task: object,
    *,
    selector_override: str | None = None,
    collision_override: str | None = None,
) -> tuple[tuple[str, bytes, int], ...]:
    """Derive copy-tree answers solely from public parameters and fixture inputs."""

    definition = bundle.definition
    manifest = _only_regular_input(definition, "input/copy-map.jsonl")
    source_prefix = "input/files/"
    sources = {
        entry.path[len(source_prefix) :]: entry
        for entry in definition.inputs
        if getattr(entry, "path", "").startswith(source_prefix)
    }
    selector = selector_override or task.parameters.selector
    policy = collision_override or task.parameters.collision_policy
    candidates: list[tuple[int, str, str, bytes]] = []
    for ordinal, record in enumerate(_parse_copy_manifest(manifest.content)):
        source_path = record["source"]
        destination = record["destination"]
        if type(source_path) is not str or type(destination) is not str:
            raise AssertionError("validated copy paths unexpectedly changed type")
        source = sources.get(source_path)
        # Exact-type checking independently enforces the no-symlink source rule.
        if type(source) is not InputFile or source.mode & 0o444 == 0:
            continue
        if selector == "txt-suffix":
            if not PurePosixPath(source_path).name.endswith(".txt"):
                continue
        elif selector == "selected-true":
            if record.get("selected") is not True:
                continue
        elif selector == "declared-sha256-matches":
            declared = record.get("sha256")
            if (
                type(declared) is not str
                or _LOWER_SHA256.fullmatch(declared) is None
                or sha256(source.content).hexdigest() != declared
            ):
                continue
        elif selector != "all-readable":
            raise AssertionError(f"unsupported reference selector: {selector}")
        candidates.append((ordinal, source_path, destination, source.content))

    by_destination: dict[str, list[tuple[int, str, str, bytes]]] = defaultdict(list)
    for candidate in candidates:
        by_destination[candidate[2]].append(candidate)

    outputs: list[tuple[str, bytes, int]] = []
    for destination, choices in by_destination.items():
        chosen: tuple[int, str, str, bytes] | None
        if len(choices) == 1:
            chosen = choices[0]
        elif policy == "reject-collision":
            chosen = None
        elif policy == "first-record":
            chosen = min(choices, key=lambda item: item[0])
        elif policy == "last-record":
            chosen = max(choices, key=lambda item: item[0])
        elif policy == "identical-bytes-only":
            chosen = choices[0] if len({item[3] for item in choices}) == 1 else None
        elif policy == "utf8-smallest-source":
            chosen = min(choices, key=lambda item: item[1].encode("utf-8"))
        else:
            raise AssertionError(f"unsupported reference collision policy: {policy}")
        if chosen is not None:
            outputs.append((f"output/{destination}", chosen[3], _OUTPUT_MODE))
    return tuple(sorted(outputs, key=lambda item: item[0].encode("utf-8")))


def _validated_checksum_record(
    path: object,
    digest: object,
    mode: object,
) -> tuple[str, str, str] | None:
    safe_path = _safe_relative_path(path)
    if (
        safe_path is None
        or type(digest) is not str
        or _LOWER_SHA256.fullmatch(digest) is None
        or type(mode) is not str
        or _OCTAL_MODE.fullmatch(mode) is None
    ):
        return None
    return safe_path, digest, mode


def _parse_checksum_manifest(
    payload: bytes,
    layout: str,
) -> tuple[tuple[str, str, str], ...]:
    """Independently decode each of the four manifest wire formats."""

    records: list[tuple[str, str, str]] = []
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
            candidate: tuple[str, str, str] | None
            if layout == "json-object-lines":
                if type(value) is not dict or set(value) != {"path", "sha256", "mode"}:
                    continue
                candidate = _validated_checksum_record(
                    value["path"], value["sha256"], value["mode"]
                )
            else:
                if type(value) is not list or len(value) != 3:
                    continue
                candidate = _validated_checksum_record(value[0], value[1], value[2])
            if candidate is not None:
                records.append(candidate)
        return tuple(records)

    if layout == "rfc4180-csv":
        try:
            text = payload.decode("utf-8", errors="strict")
            rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
        except (UnicodeDecodeError, csv.Error):
            return ()
        if not rows or rows[0] != ["path", "sha256", "mode"]:
            return ()
        for row in rows[1:]:
            candidate = (
                _validated_checksum_record(row[0], row[1], row[2])
                if len(row) == 3
                else None
            )
            if candidate is not None:
                records.append(candidate)
        return tuple(records)

    if layout == "nul-triplets":
        fields = payload.split(b"\0")
        if fields and fields[-1] == b"":
            fields.pop()
        complete_field_count = len(fields) - len(fields) % 3
        for offset in range(0, complete_field_count, 3):
            try:
                path, digest, mode = (
                    field.decode("utf-8", errors="strict")
                    for field in fields[offset : offset + 3]
                )
            except UnicodeDecodeError:
                continue
            candidate = _validated_checksum_record(path, digest, mode)
            if candidate is not None:
                records.append(candidate)
        return tuple(records)

    raise AssertionError(f"unsupported reference checksum layout: {layout}")


def _checksum_asset_state(
    definition: object,
) -> tuple[dict[str, object], frozenset[str]]:
    prefix = "input/assets/"
    entries: dict[str, object] = {}
    directories: set[str] = set()
    for entry in definition.inputs:
        path = getattr(entry, "path", "")
        if not path.startswith(prefix):
            continue
        relative = path[len(prefix) :]
        entries[relative] = entry
        relative_path = PurePosixPath(relative)
        directories.update(
            parent.as_posix()
            for parent in relative_path.parents
            if parent != PurePosixPath(".")
        )
    return entries, frozenset(directories)


def _reference_checksum_status(
    record: tuple[str, str, str],
    *,
    policy: str,
    entries: dict[str, object],
    directories: frozenset[str],
) -> str:
    path, expected_digest, expected_mode = record
    entry = entries.get(path)
    if entry is None and path in directories:
        kind = "directory"
    elif entry is None:
        kind = "missing"
    elif type(entry) is InputFile:
        kind = "regular"
    elif type(entry) is InputSymlink:
        kind = "symlink"
    else:
        kind = "other_kind"

    if policy == "strict-kind-digest-and-mode":
        if kind != "regular":
            return kind
    elif policy == "readable-digest-and-mode":
        if kind == "missing":
            return "missing"
        if kind != "regular":
            return "not_regular"
    elif policy in {"digest-only", "mode-only", "digest-and-mode"}:
        if kind != "regular":
            return "unavailable"
    else:
        raise AssertionError(f"unsupported reference checksum policy: {policy}")

    if type(entry) is not InputFile:
        raise AssertionError("regular checksum reference did not resolve a file")
    if policy != "mode-only" and entry.mode & 0o444 == 0:
        if policy in {"readable-digest-and-mode", "strict-kind-digest-and-mode"}:
            return "unreadable"
        return "unavailable"

    mode_matches = f"{entry.mode:03o}" == expected_mode
    digest_matches = sha256(entry.content).hexdigest() == expected_digest
    if policy == "digest-only":
        return "ok" if digest_matches else "checksum_mismatch"
    if policy == "mode-only":
        return "ok" if mode_matches else "mode_mismatch"
    if digest_matches and mode_matches:
        return "ok"
    if not digest_matches and not mode_matches:
        return "checksum_and_mode_mismatch"
    if not digest_matches:
        return "checksum_mismatch"
    return "mode_mismatch"


def _render_status_rows(rows: list[tuple[int, str, str]]) -> bytes:
    rows.sort(key=lambda item: (item[1].encode("utf-8"), item[0]))
    return "".join(
        json.dumps(
            {"path": path, "status": status},
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
        for _ordinal, path, status in rows
    ).encode("utf-8")


def _reference_checksum_outputs(
    bundle: object,
    task: object,
    *,
    policy_override: str | None = None,
) -> tuple[tuple[str, bytes, int], ...]:
    definition = bundle.definition
    manifest = _only_regular_input(definition, "input/manifest.data")
    entries, directories = _checksum_asset_state(definition)
    policy = policy_override or task.parameters.policy
    records = _parse_checksum_manifest(manifest.content, task.parameters.layout)
    rows = [
        (
            ordinal,
            record[0],
            _reference_checksum_status(
                record,
                policy=policy,
                entries=entries,
                directories=directories,
            ),
        )
        for ordinal, record in enumerate(records)
    ]
    return (("output/report.jsonl", _render_status_rows(rows), _OUTPUT_MODE),)


def _oracle_outputs(bundle: object) -> tuple[tuple[str, bytes, int], ...]:
    return tuple(
        (output.path, output.content, output.mode) for output in bundle.oracle.outputs
    )


def _task_by_parameters(family: str, **values: object) -> object:
    matches = tuple(
        task
        for task in RECORD_TASKS
        if task.family_id == family
        and all(getattr(task.parameters, field) == value for field, value in values.items())
    )
    if len(matches) != 1:
        raise AssertionError(f"record task lookup was not unique: {family} {values}")
    return matches[0]


def _replace_first_status(content: bytes, *, path: str, wrong_status: str) -> bytes:
    decoded = [json.loads(line) for line in content.decode("utf-8").splitlines()]
    replaced = False
    rows: list[tuple[int, str, str]] = []
    for ordinal, row in enumerate(decoded):
        status = row["status"]
        if not replaced and row["path"] == path:
            status = wrong_status
            replaced = True
        rows.append((ordinal, row["path"], status))
    if not replaced:
        raise AssertionError(f"status mutation target is absent: {path}")
    return _render_status_rows(rows)


class RecordFixtureIndependentReferenceTests(unittest.TestCase):
    def test_reference_matches_all_200_record_bundles_exactly(self) -> None:
        self.assertEqual(len(RECORD_TASKS), 40)
        self.assertEqual(
            {task.parameters.selector for task in RECORD_TASKS if task.family_id == "manifest-copy"},
            {
                "all-readable",
                "txt-suffix",
                "selected-true",
                "declared-sha256-matches",
            },
        )
        self.assertEqual(
            {task.parameters.collision_policy for task in RECORD_TASKS if task.family_id == "manifest-copy"},
            {
                "reject-collision",
                "first-record",
                "last-record",
                "identical-bytes-only",
                "utf8-smallest-source",
            },
        )
        self.assertEqual(
            {task.parameters.layout for task in RECORD_TASKS if task.family_id == "checksum-manifest"},
            {"json-object-lines", "json-array-lines", "rfc4180-csv", "nul-triplets"},
        )
        self.assertEqual(
            {task.parameters.policy for task in RECORD_TASKS if task.family_id == "checksum-manifest"},
            {
                "digest-only",
                "mode-only",
                "digest-and-mode",
                "readable-digest-and-mode",
                "strict-kind-digest-and-mode",
            },
        )

        checked = 0
        with mock.patch.object(
            subprocess,
            "run",
            side_effect=AssertionError("reference audit must not execute subprocesses"),
        ), mock.patch.object(
            subprocess,
            "Popen",
            side_effect=AssertionError("reference audit must not execute subprocesses"),
        ):
            for task in RECORD_TASKS:
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                    if task.family_id == "manifest-copy":
                        bundle = build_manifest_copy_fixture_bundle(task, profile)
                        reference = _reference_manifest_outputs(bundle, task)
                    else:
                        bundle = build_checksum_manifest_fixture_bundle(task, profile)
                        reference = _reference_checksum_outputs(bundle, task)
                    with self.subTest(
                        family=task.family_id,
                        parameters=task.parameters,
                        profile=profile.profile_id,
                    ):
                        self.assertEqual(_oracle_outputs(bundle), reference)
                        self.assertEqual(
                            tuple(
                                (expected.path, expected.mode)
                                for expected in bundle.definition.expected_files
                            ),
                            tuple((path, mode) for path, _content, mode in reference),
                        )
                    checked += 1
        self.assertEqual(checked, 40 * 5)

    def test_reference_rejects_plausible_collision_policy_mutations(self) -> None:
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        wrong_policy = {
            "reject-collision": "first-record",
            "first-record": "last-record",
            "last-record": "first-record",
            "identical-bytes-only": "reject-collision",
            "utf8-smallest-source": "first-record",
        }
        for policy, mutation in wrong_policy.items():
            task = _task_by_parameters(
                "manifest-copy",
                selector="all-readable",
                collision_policy=policy,
            )
            bundle = build_manifest_copy_fixture_bundle(task, profile)
            reference = _reference_manifest_outputs(bundle, task)
            mutated = _reference_manifest_outputs(
                bundle,
                task,
                collision_override=mutation,
            )
            with self.subTest(policy=policy, wrong_policy=mutation):
                self.assertEqual(reference, _oracle_outputs(bundle))
                self.assertNotEqual(mutated, reference)

    def test_reference_rejects_plausible_checksum_policy_mutations(self) -> None:
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        wrong_policy = {
            "digest-only": "mode-only",
            "mode-only": "digest-only",
            "digest-and-mode": "digest-only",
            "readable-digest-and-mode": "strict-kind-digest-and-mode",
            "strict-kind-digest-and-mode": "readable-digest-and-mode",
        }
        for policy, mutation in wrong_policy.items():
            task = _task_by_parameters(
                "checksum-manifest",
                layout="json-object-lines",
                policy=policy,
            )
            bundle = build_checksum_manifest_fixture_bundle(task, profile)
            reference = _reference_checksum_outputs(bundle, task)
            mutated = _reference_checksum_outputs(
                bundle,
                task,
                policy_override=mutation,
            )
            with self.subTest(policy=policy, wrong_policy=mutation):
                self.assertEqual(reference, _oracle_outputs(bundle))
                self.assertNotEqual(mutated, reference)

    def test_reference_rejects_targeted_wrong_statuses(self) -> None:
        profile = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES[0]
        mutations = (
            ("digest-only", "missing.file", "missing"),
            ("mode-only", "unreadable.bin", "unavailable"),
            ("digest-and-mode", "한글 자료.bin", "checksum_mismatch"),
            ("readable-digest-and-mode", "directory", "directory"),
            ("strict-kind-digest-and-mode", "link-to-first", "not_regular"),
        )
        for policy, path, wrong_status in mutations:
            task = _task_by_parameters(
                "checksum-manifest",
                layout="json-object-lines",
                policy=policy,
            )
            bundle = build_checksum_manifest_fixture_bundle(task, profile)
            reference = _reference_checksum_outputs(bundle, task)
            path_name, content, mode = reference[0]
            mutated = (
                (
                    path_name,
                    _replace_first_status(
                        content,
                        path=path,
                        wrong_status=wrong_status,
                    ),
                    mode,
                ),
            )
            with self.subTest(policy=policy, path=path, wrong_status=wrong_status):
                self.assertEqual(reference, _oracle_outputs(bundle))
                self.assertNotEqual(mutated, reference)


if __name__ == "__main__":
    unittest.main()
