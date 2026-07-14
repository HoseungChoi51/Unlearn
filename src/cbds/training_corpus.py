"""Content-addressed training-corpus preparation for the backbone pilot.

This module deliberately stops before tokenization.  It imports only the
explicitly pinned NL2SH-ALFA *training* CSV, generates a deterministic replay
corpus for target prerequisites, and writes canonical JSONL plus a manifest.
The upstream command pairs remain labelled unverified; preparation never turns
source provenance into a quality claim.

Tokenizer-specific schedules are a separate artifact because the three pilot
models do not share a tokenizer.  Keeping the logical corpus independent of a
tokenizer makes the record order and source identity comparable while allowing
each later schedule to account exact optimizer-visible tokens.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import ctypes
import csv
import errno
from hashlib import sha256
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import platform
from typing import Any, Final

from .manifests import canonical_json_bytes, load_document, value_sha256


CORPUS_SCHEMA_VERSION: Final[str] = "1.0.0"
CORPUS_PREPARER_VERSION: Final[str] = "1.0.0"
RECORD_SCHEMA_VERSION: Final[str] = "1.0.0"
SUPPORT_GENERATOR_VERSION: Final[str] = "1.0.0"
TARGET_FILE_NAME: Final[str] = "target.jsonl"
SUPPORT_FILE_NAME: Final[str] = "support.jsonl"
MANIFEST_FILE_NAME: Final[str] = "manifest.json"
MANIFEST_SIDECAR_NAME: Final[str] = "manifest.sha256"
_CORPUS_MEMBER_NAMES: Final[frozenset[str]] = frozenset(
    {TARGET_FILE_NAME, SUPPORT_FILE_NAME, MANIFEST_FILE_NAME, MANIFEST_SIDECAR_NAME}
)
MAX_SOURCE_BYTES: Final[int] = 64 * 1024 * 1024
MAX_PARTITION_BYTES: Final[int] = 256 * 1024 * 1024
MAX_RECORDS_PER_PARTITION: Final[int] = 100_000
MAX_PROMPT_UTF8_BYTES: Final[int] = 64 * 1024
MAX_COMPLETION_UTF8_BYTES: Final[int] = 64 * 1024

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_REVISION_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}\Z")
_ID_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9._-]{2,127}\Z")
_SUPPORT_FAMILIES: Final[tuple[str, ...]] = (
    "instruction_following",
    "basic_numeracy",
    "structured_json",
    "structured_yaml",
    "python_stdlib",
    "unix_regex_concepts",
)
_RECORD_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "record_id",
        "record_sha256",
        "partition",
        "family",
        "prompt",
        "completion",
        "source",
    }
)
_TARGET_RECORD_SOURCE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "repository",
        "revision",
        "split",
        "relative_path",
        "file_sha256",
        "row_number",
        "verification_status",
    }
)
_SUPPORT_RECORD_SOURCE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "generator",
        "version",
        "seed",
        "family_index",
        "verification_status",
    }
)
_PREPARER_NAME: Final[str] = "cbds.training_corpus"
_QUALITY_SCOPE: Final[dict[str, object]] = {
    "target": "unverified_upstream_pairs",
    "support": "deterministic_reference_generator_not_human_audited",
    "claim_authorized": False,
}
_LIMITATIONS: Final[tuple[str, ...]] = (
    "NL2SH-ALFA training pairs are upstream-unverified.",
    "The source combines NL2Bash, LinuxCommands, NL2CMD, InterCode-Bash, and tldr-pages without row-level lineage; the repository-level MIT declaration is not treated as row-level license clearance.",
    "The generated prerequisite replay is deterministic but has not received a stratified human audit.",
    "The imported target contains single-line, unparsed strings; it includes placeholders and out-of-policy utilities and is not a substitute for policy-filtered, execution-verified terminal training data.",
    "No tokenizer, token schedule, model training, execution score, model-selection decision, or research claim is represented.",
    "The NL2SH-ALFA test CSV is explicitly excluded and was not imported.",
)


class TrainingCorpusError(ValueError):
    """Fail-closed error for corpus preparation or verification."""

    def __init__(self, issues: str | Iterable[str]) -> None:
        normalized = (issues,) if isinstance(issues, str) else tuple(issues)
        if not normalized:
            normalized = ("training corpus validation failed",)
        self.issues = tuple(str(item) for item in normalized)
        super().__init__("training corpus validation failed:\n- " + "\n- ".join(self.issues))


class _RFC4180Error(ValueError):
    pass


def _exact_keys(value: object, expected: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TrainingCorpusError(f"{label} must be an object")
    keys = set(value)
    if keys != expected:
        missing = sorted(expected - keys)
        extra = sorted(keys - expected)
        raise TrainingCorpusError(
            f"{label} keys differ; missing={missing!r}, extra={extra!r}"
        )
    return value


def _string(value: object, label: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        raise TrainingCorpusError(f"{label} must be a nonempty string")
    if "\x00" in value:
        raise TrainingCorpusError(f"{label} must not contain NUL")
    return value


def _sha256(value: object, label: str) -> str:
    text = _string(value, label)
    if _SHA256_RE.fullmatch(text) is None:
        raise TrainingCorpusError(f"{label} must be a lowercase SHA-256")
    return text


def _positive_int(value: object, label: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise TrainingCorpusError(f"{label} must be a positive integer")
    if value > maximum:
        raise TrainingCorpusError(f"{label} exceeds {maximum}")
    return value


def _safe_relative(value: object, label: str) -> str:
    text = _string(value, label)
    if "\\" in text or any(ord(character) < 32 or ord(character) == 127 for character in text):
        raise TrainingCorpusError(f"{label} contains a backslash or control character")
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or text != path.as_posix()
    ):
        raise TrainingCorpusError(f"{label} must be a canonical safe relative path")
    return path.as_posix()


_CONFIG_KEYS = frozenset(
    {"schema_version", "corpus_id", "seed", "target_source", "support_source", "formatting"}
)
_TARGET_KEYS = frozenset(
    {
        "repository",
        "revision",
        "relative_path",
        "file_sha256",
        "dataset_card_relative_path",
        "dataset_card_sha256",
        "license_provenance",
        "split",
        "prompt_column",
        "completion_column",
        "expected_rows",
        "expected_unique_pairs",
        "duplicate_policy",
        "verification_status",
        "excluded_relative_paths",
    }
)
_SUPPORT_KEYS = frozenset(
    {
        "generator",
        "version",
        "license_provenance",
        "seed",
        "records_per_family",
        "families",
        "verification_status",
    }
)
_FORMATTING_KEYS = frozenset(
    {"template", "separator", "add_eos", "text_normalization", "loss_scope"}
)
_TARGET_LICENSE_PROVENANCE = {
    "upstream_declared_license": "MIT",
    "declaration_scope": "dataset_repository_level",
    "row_level_lineage": "unavailable",
    "component_license_map": "not_verified",
    "redistribution_clearance": "unresolved",
    "upstream_components": [
        "NL2Bash",
        "LinuxCommands",
        "NL2CMD",
        "InterCode-Bash",
        "tldr-pages",
    ],
}
_SUPPORT_LICENSE_PROVENANCE = {
    "authorship": "generated_by_this_repository",
    "project_license": "none_declared",
    "redistribution_clearance": "unresolved",
}


def validate_training_corpus_config(config: object) -> dict[str, Any]:
    """Validate and return a detached canonical copy of a corpus config."""

    root = _exact_keys(config, _CONFIG_KEYS, "config")
    if root["schema_version"] != CORPUS_SCHEMA_VERSION:
        raise TrainingCorpusError(
            f"config.schema_version must equal {CORPUS_SCHEMA_VERSION!r}"
        )
    corpus_id = _string(root["corpus_id"], "config.corpus_id")
    if _ID_RE.fullmatch(corpus_id) is None:
        raise TrainingCorpusError("config.corpus_id is not a canonical identifier")
    seed = root["seed"]
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise TrainingCorpusError("config.seed must be an integer")

    target = _exact_keys(root["target_source"], _TARGET_KEYS, "config.target_source")
    repository = _string(target["repository"], "config.target_source.repository")
    revision = _string(target["revision"], "config.target_source.revision")
    if _REVISION_RE.fullmatch(revision) is None:
        raise TrainingCorpusError("config.target_source.revision must be a 40-hex revision")
    relative_path = _safe_relative(target["relative_path"], "config.target_source.relative_path")
    if PurePosixPath(relative_path).name != "train.csv":
        raise TrainingCorpusError("target source must be the pinned train.csv")
    file_digest = _sha256(target["file_sha256"], "config.target_source.file_sha256")
    card_relative_path = _safe_relative(
        target["dataset_card_relative_path"],
        "config.target_source.dataset_card_relative_path",
    )
    if PurePosixPath(card_relative_path).name != "README.md":
        raise TrainingCorpusError("target dataset card must be the pinned README.md")
    if card_relative_path == relative_path:
        raise TrainingCorpusError("target data and dataset card paths must differ")
    card_digest = _sha256(
        target["dataset_card_sha256"], "config.target_source.dataset_card_sha256"
    )
    license_provenance = target["license_provenance"]
    if (
        not isinstance(license_provenance, Mapping)
        or dict(license_provenance) != _TARGET_LICENSE_PROVENANCE
    ):
        raise TrainingCorpusError(
            "config.target_source.license_provenance must preserve the frozen unresolved lineage status"
        )
    if target["split"] != "train":
        raise TrainingCorpusError("config.target_source.split must equal 'train'")
    prompt_column = _string(target["prompt_column"], "config.target_source.prompt_column")
    completion_column = _string(
        target["completion_column"], "config.target_source.completion_column"
    )
    if prompt_column == completion_column:
        raise TrainingCorpusError("prompt and completion columns must differ")
    expected_rows = _positive_int(
        target["expected_rows"], "config.target_source.expected_rows", maximum=MAX_RECORDS_PER_PARTITION
    )
    expected_unique = _positive_int(
        target["expected_unique_pairs"],
        "config.target_source.expected_unique_pairs",
        maximum=expected_rows,
    )
    if target["duplicate_policy"] != "keep_first_exact_pair":
        raise TrainingCorpusError(
            "config.target_source.duplicate_policy must equal 'keep_first_exact_pair'"
        )
    if target["verification_status"] != "unverified_upstream_pairs":
        raise TrainingCorpusError(
            "target verification_status must preserve 'unverified_upstream_pairs'"
        )
    excluded = target["excluded_relative_paths"]
    if not isinstance(excluded, list) or not excluded:
        raise TrainingCorpusError("target excluded_relative_paths must be a nonempty array")
    excluded_paths = tuple(
        _safe_relative(item, f"config.target_source.excluded_relative_paths[{index}]")
        for index, item in enumerate(excluded)
    )
    if len(set(excluded_paths)) != len(excluded_paths) or "test.csv" not in excluded_paths:
        raise TrainingCorpusError("excluded_relative_paths must uniquely include test.csv")
    if relative_path in excluded_paths:
        raise TrainingCorpusError("target source path cannot also be excluded")

    support = _exact_keys(root["support_source"], _SUPPORT_KEYS, "config.support_source")
    if support["generator"] != "cbds_prerequisite_replay":
        raise TrainingCorpusError(
            "config.support_source.generator must equal 'cbds_prerequisite_replay'"
        )
    if support["version"] != SUPPORT_GENERATOR_VERSION:
        raise TrainingCorpusError(
            f"config.support_source.version must equal {SUPPORT_GENERATOR_VERSION!r}"
        )
    support_license_provenance = support["license_provenance"]
    if (
        not isinstance(support_license_provenance, Mapping)
        or dict(support_license_provenance) != _SUPPORT_LICENSE_PROVENANCE
    ):
        raise TrainingCorpusError(
            "config.support_source.license_provenance must preserve the no-license unresolved status"
        )
    support_seed = support["seed"]
    if isinstance(support_seed, bool) or not isinstance(support_seed, int):
        raise TrainingCorpusError("config.support_source.seed must be an integer")
    if support_seed != seed:
        raise TrainingCorpusError(
            "config.support_source.seed must equal config.seed because the root seed drives corpus generation"
        )
    records_per_family = _positive_int(
        support["records_per_family"],
        "config.support_source.records_per_family",
        maximum=10_000,
    )
    families = support["families"]
    if not isinstance(families, list) or tuple(families) != _SUPPORT_FAMILIES:
        raise TrainingCorpusError(
            "config.support_source.families must equal the frozen ordered family list"
        )
    if support["verification_status"] != "deterministic_reference_generator":
        raise TrainingCorpusError(
            "support verification_status must equal 'deterministic_reference_generator'"
        )

    formatting = _exact_keys(root["formatting"], _FORMATTING_KEYS, "config.formatting")
    expected_formatting = {
        "template": "### Instruction\n{prompt}\n\n### Response\n{completion}",
        "separator": "tokenizer_eos_token",
        "add_eos": True,
        "text_normalization": "crlf_and_cr_to_lf_no_unicode_normalization",
        "loss_scope": "assistant_response_tokens",
    }
    if dict(formatting) != expected_formatting:
        raise TrainingCorpusError("config.formatting does not equal the frozen pilot policy")

    normalized = {
        "schema_version": CORPUS_SCHEMA_VERSION,
        "corpus_id": corpus_id,
        "seed": seed,
        "target_source": {
            "repository": repository,
            "revision": revision,
            "relative_path": relative_path,
            "file_sha256": file_digest,
            "dataset_card_relative_path": card_relative_path,
            "dataset_card_sha256": card_digest,
            "license_provenance": _TARGET_LICENSE_PROVENANCE,
            "split": "train",
            "prompt_column": prompt_column,
            "completion_column": completion_column,
            "expected_rows": expected_rows,
            "expected_unique_pairs": expected_unique,
            "duplicate_policy": "keep_first_exact_pair",
            "verification_status": "unverified_upstream_pairs",
            "excluded_relative_paths": list(excluded_paths),
        },
        "support_source": {
            "generator": "cbds_prerequisite_replay",
            "version": SUPPORT_GENERATOR_VERSION,
            "license_provenance": _SUPPORT_LICENSE_PROVENANCE,
            "seed": support_seed,
            "records_per_family": records_per_family,
            "families": list(_SUPPORT_FAMILIES),
            "verification_status": "deterministic_reference_generator",
        },
        "formatting": expected_formatting,
    }
    # Round-trip through canonical JSON to detach hostile Mapping subclasses.
    return json.loads(canonical_json_bytes(normalized))


def training_corpus_config_sha256(config: object) -> str:
    return value_sha256(validate_training_corpus_config(config))


def _fingerprint(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _directory_open_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", None)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if directory is None or nofollow is None:  # pragma: no cover - Linux requirement
        raise TrainingCorpusError("platform lacks O_DIRECTORY or O_NOFOLLOW")
    return os.O_RDONLY | os.O_CLOEXEC | directory | nofollow


def _open_directory_path(
    path: Path,
    *,
    create: bool,
) -> int:
    """Open a directory component-by-component without following symlinks."""

    absolute = Path(os.path.abspath(path))
    descriptor = os.open("/", _directory_open_flags())
    try:
        for part in absolute.parts[1:]:
            if part in {"", ".", ".."}:
                raise TrainingCorpusError("directory path is not canonical")
            if create:
                try:
                    os.mkdir(part, mode=0o755, dir_fd=descriptor)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise TrainingCorpusError(
                        f"cannot create output parent: {type(exc).__name__}"
                    ) from exc
            try:
                child = os.open(part, _directory_open_flags(), dir_fd=descriptor)
                named = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                opened = os.fstat(child)
            except OSError as exc:
                raise TrainingCorpusError(
                    f"cannot open directory path: {type(exc).__name__}"
                ) from exc
            if (
                named.st_dev != opened.st_dev
                or named.st_ino != opened.st_ino
                or not stat.S_ISDIR(named.st_mode)
            ):
                os.close(child)
                raise TrainingCorpusError("directory component changed while opening")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_stable_source(path: Path, *, maximum_bytes: int) -> bytes:
    """Read a regular source, permitting an HF snapshot symlink by pinning its target."""

    try:
        original_before = path.lstat()
    except OSError as exc:
        raise TrainingCorpusError(f"cannot inspect target source: {type(exc).__name__}") from exc
    link_text: str | None = None
    if stat.S_ISLNK(original_before.st_mode):
        try:
            link_text = os.readlink(path)
            opened_path = path.resolve(strict=True)
        except OSError as exc:
            raise TrainingCorpusError(f"cannot resolve target source link: {type(exc).__name__}") from exc
    else:
        opened_path = path
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:  # pragma: no cover - Linux research requirement
        raise TrainingCorpusError("platform lacks O_NOFOLLOW")
    flags |= nofollow
    try:
        descriptor = os.open(opened_path, flags)
    except OSError as exc:
        raise TrainingCorpusError(f"cannot open target source: {type(exc).__name__}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise TrainingCorpusError("target source must resolve to a regular file")
        if before.st_size > maximum_bytes:
            raise TrainingCorpusError(f"target source exceeds {maximum_bytes} bytes")
        payload = bytearray()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise TrainingCorpusError("target source ended before its snapshotted size")
            payload.extend(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise TrainingCorpusError("target source grew beyond its snapshotted size")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _fingerprint(before) != _fingerprint(after):
        raise TrainingCorpusError("target source changed while being read")
    try:
        original_after = path.lstat()
        if _fingerprint(original_before) != _fingerprint(original_after):
            raise TrainingCorpusError("target source path changed while being read")
        if link_text is not None and os.readlink(path) != link_text:
            raise TrainingCorpusError("target source symlink changed while being read")
    except OSError as exc:
        raise TrainingCorpusError(f"cannot recheck target source: {type(exc).__name__}") from exc
    return bytes(payload)


def _preparer_identity() -> dict[str, Any]:
    package_root = Path(__file__).resolve(strict=True).parent
    implementations = []
    for logical_name in ("manifests.py", "training_corpus.py"):
        payload = _read_stable_source(
            package_root / logical_name,
            maximum_bytes=4 * 1024 * 1024,
        )
        implementations.append(
            {
                "path": f"cbds/{logical_name}",
                "bytes": len(payload),
                "sha256": sha256(payload).hexdigest(),
            }
        )
    return {
        "name": _PREPARER_NAME,
        "version": CORPUS_PREPARER_VERSION,
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "implementation_files": implementations,
    }


def _validate_preparer_identity(value: object) -> dict[str, Any]:
    root = _exact_keys(
        value,
        frozenset(
            {
                "name",
                "version",
                "python_implementation",
                "python_version",
                "implementation_files",
            }
        ),
        "manifest.preparer",
    )
    if root["name"] != _PREPARER_NAME or root["version"] != CORPUS_PREPARER_VERSION:
        raise TrainingCorpusError("manifest preparer name or version is invalid")
    _string(root["python_implementation"], "manifest.preparer.python_implementation")
    _string(root["python_version"], "manifest.preparer.python_version")
    files = root["implementation_files"]
    if not isinstance(files, list) or len(files) != 2:
        raise TrainingCorpusError("manifest preparer must bind exactly two implementation files")
    expected_paths = ["cbds/manifests.py", "cbds/training_corpus.py"]
    for index, (item, expected_path) in enumerate(zip(files, expected_paths, strict=True)):
        entry = _exact_keys(
            item,
            frozenset({"path", "bytes", "sha256"}),
            f"manifest.preparer.implementation_files[{index}]",
        )
        if entry["path"] != expected_path:
            raise TrainingCorpusError("manifest preparer implementation-file order is invalid")
        _positive_int(
            entry["bytes"],
            f"manifest.preparer.implementation_files[{index}].bytes",
            maximum=4 * 1024 * 1024,
        )
        _sha256(
            entry["sha256"],
            f"manifest.preparer.implementation_files[{index}].sha256",
        )
    return json.loads(canonical_json_bytes(root))


def _validate_rfc4180_syntax(text: str) -> None:
    offset = 0
    length = len(text)
    while offset < length:
        if text[offset] == '"':
            offset += 1
            while True:
                if offset >= length:
                    raise _RFC4180Error("unterminated quoted field")
                if text[offset] != '"':
                    offset += 1
                    continue
                if offset + 1 < length and text[offset + 1] == '"':
                    offset += 2
                    continue
                offset += 1
                break
            if offset < length and text[offset] not in {",", "\r", "\n"}:
                raise _RFC4180Error("characters follow a closing quote")
        else:
            while offset < length and text[offset] not in {",", "\r", "\n"}:
                if text[offset] == '"':
                    raise _RFC4180Error("quote appears in an unquoted field")
                offset += 1
        if offset >= length:
            break
        if text[offset] == ",":
            offset += 1
        elif text[offset] == "\n":
            offset += 1
        elif offset + 1 < length and text[offset + 1] == "\n":
            offset += 2
        else:
            raise _RFC4180Error("bare CR record delimiter")


def _normalize_text(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _record(
    *, partition: str, family: str, prompt: str, completion: str, source: Mapping[str, Any]
) -> dict[str, Any]:
    if partition not in {"target", "support"}:
        raise TrainingCorpusError("record partition is invalid")
    _string(family, "record.family")
    prompt = _normalize_text(_string(prompt, "record.prompt"))
    completion = _normalize_text(_string(completion, "record.completion"))
    if len(prompt.encode("utf-8")) > MAX_PROMPT_UTF8_BYTES:
        raise TrainingCorpusError("record prompt exceeds the UTF-8 byte limit")
    if len(completion.encode("utf-8")) > MAX_COMPLETION_UTF8_BYTES:
        raise TrainingCorpusError("record completion exceeds the UTF-8 byte limit")
    core: dict[str, Any] = {
        "schema_version": RECORD_SCHEMA_VERSION,
        "partition": partition,
        "family": family,
        "prompt": prompt,
        "completion": completion,
        "source": json.loads(canonical_json_bytes(source)),
    }
    digest = value_sha256(core)
    return {
        "schema_version": RECORD_SCHEMA_VERSION,
        "record_id": f"tr-{digest[:24]}",
        "record_sha256": digest,
        "partition": partition,
        "family": family,
        "prompt": prompt,
        "completion": completion,
        "source": core["source"],
    }


def _target_records(payload: bytes, config: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    target = config["target_source"]
    if sha256(payload).hexdigest() != target["file_sha256"]:
        raise TrainingCorpusError("target source SHA-256 does not match the pinned config")
    try:
        text = payload.decode("utf-8", errors="strict")
        _validate_rfc4180_syntax(text)
        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        header = next(reader)
    except (UnicodeDecodeError, csv.Error, _RFC4180Error, StopIteration) as exc:
        raise TrainingCorpusError("target source is not valid UTF-8 RFC 4180 CSV") from exc
    expected_header = [target["prompt_column"], target["completion_column"]]
    if header != expected_header:
        raise TrainingCorpusError("target CSV header does not match the pinned columns")
    seen: set[tuple[str, str]] = set()
    records: list[dict[str, Any]] = []
    rows = 0
    try:
        for row_number, row in enumerate(reader, start=2):
            rows += 1
            if len(row) != 2:
                raise TrainingCorpusError(f"target CSV row {row_number} does not have two fields")
            prompt = _normalize_text(row[0])
            completion = _normalize_text(row[1])
            _string(prompt, f"target CSV row {row_number} prompt")
            _string(completion, f"target CSV row {row_number} completion")
            if "\n" in completion:
                raise TrainingCorpusError(
                    f"target CSV row {row_number} completion is not a single-line Bash command"
                )
            pair = (prompt, completion)
            if pair in seen:
                continue
            seen.add(pair)
            records.append(
                _record(
                    partition="target",
                    family="nl2sh_single_line_unparsed",
                    prompt=prompt,
                    completion=completion,
                    source={
                        "repository": target["repository"],
                        "revision": target["revision"],
                        "split": "train",
                        "relative_path": target["relative_path"],
                        "file_sha256": target["file_sha256"],
                        "row_number": row_number,
                        "verification_status": "unverified_upstream_pairs",
                    },
                )
            )
    except csv.Error as exc:
        raise TrainingCorpusError("target CSV parser failed") from exc
    if rows != target["expected_rows"]:
        raise TrainingCorpusError(
            f"target CSV row count is {rows}, expected {target['expected_rows']}"
        )
    if len(records) != target["expected_unique_pairs"]:
        raise TrainingCorpusError(
            "target CSV unique-pair count does not match the pinned config"
        )
    return tuple(records)


def _stable_number(seed: int, family: str, index: int, slot: int, modulus: int) -> int:
    material = f"{seed}:{family}:{index}:{slot}".encode("ascii")
    return int.from_bytes(sha256(material).digest()[:8], "big") % modulus


def _support_example(family: str, index: int, seed: int) -> tuple[str, str]:
    # Keep one operand injective in the family-local index so arithmetic
    # examples cannot collide even when the pseudorandom operands repeat.
    a = 2 + index
    b = 2 + _stable_number(seed, family, index, 1, 89)
    c = 1 + _stable_number(seed, family, index, 2, 43)
    # The index makes family-local uniqueness deterministic.  A truncated
    # digest alone made uniqueness probabilistic and produced real collisions
    # in the 512-example pilot corpus.
    token = (
        f"{index:04x}_"
        f"{sha256(f'{seed}:{family}:{index}'.encode('ascii')).hexdigest()[:10]}"
    )
    if family == "instruction_following":
        items = [f"item-{token}-{position}" for position in range(4)]
        selected = _stable_number(seed, family, index, 3, len(items))
        prompt = (
            "Follow the instruction exactly. From the ordered JSON array "
            f"{json.dumps(items, separators=(',', ':'))}, return only a canonical "
            f"JSON object whose key is answer and whose value is item {selected + 1}."
        )
        completion = json.dumps({"answer": items[selected]}, sort_keys=True, separators=(",", ":"))
    elif family == "basic_numeracy":
        prompt = f"Compute ({a} * {b}) + {c}. Return only the base-10 integer."
        completion = str(a * b + c)
    elif family == "structured_json":
        source = {"name": f"record-{token}", "left": a, "right": b, "enabled": index % 2 == 0}
        prompt = (
            f"Given {json.dumps(source, sort_keys=True, separators=(',', ':'))}, "
            "return canonical JSON with keys enabled, name, and total, where total is left plus right."
        )
        completion = json.dumps(
            {"enabled": source["enabled"], "name": source["name"], "total": a + b},
            sort_keys=True,
            separators=(",", ":"),
        )
    elif family == "structured_yaml":
        prompt = (
            "Return only a YAML mapping, in key order name, enabled, count, for "
            f"name item-{token}, enabled {'true' if index % 2 == 0 else 'false'}, count {a}."
        )
        completion = (
            f"name: item-{token}\n"
            f"enabled: {'true' if index % 2 == 0 else 'false'}\n"
            f"count: {a}"
        )
    elif family == "python_stdlib":
        variants = index % 4
        if variants == 0:
            prompt = f"Write only Python code for a function add_{token}(left, right) that returns their sum plus {c}."
            completion = f"def add_{token}(left, right):\n    return left + right + {c}"
        elif variants == 1:
            prompt = (
                "Write only Python code using json.loads to assign the value "
                f"at key {token!r} from a JSON string named text to a variable named value."
            )
            completion = f"import json\nvalue = json.loads(text)[{token!r}]"
        elif variants == 2:
            prompt = f"Write only Python code using pathlib to count .txt files below directory root and store the count in count_{token}."
            completion = f"from pathlib import Path\ncount_{token} = sum(1 for p in Path(root).rglob('*.txt') if p.is_file())"
        else:
            prompt = f"Write only Python code using csv.reader to sum integer column {index % 5} from iterable rows into total_{token}."
            completion = f"import csv\ntotal_{token} = sum(int(row[{index % 5}]) for row in csv.reader(rows))"
    elif family == "unix_regex_concepts":
        suffix = token
        prompt = (
            "Return only an extended regular expression that matches strings beginning "
            f"with log-, followed by exactly {1 + index % 4} digits, and ending with -{suffix}."
        )
        completion = f"^log-[0-9]{{{1 + index % 4}}}-{suffix}$"
    else:  # pragma: no cover - protected by the frozen family list
        raise TrainingCorpusError(f"unsupported support family {family!r}")
    return prompt, completion


def _support_records(config: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    support = config["support_source"]
    records: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str, str]] = set()
    for family in _SUPPORT_FAMILIES:
        for index in range(support["records_per_family"]):
            prompt, completion = _support_example(family, index, support["seed"])
            if (prompt, completion) in seen_pairs:
                raise TrainingCorpusError("support generator produced a duplicate pair")
            seen_pairs.add((prompt, completion))
            records.append(
                _record(
                    partition="support",
                    family=family,
                    prompt=prompt,
                    completion=completion,
                    source={
                        "generator": support["generator"],
                        "version": support["version"],
                        "seed": support["seed"],
                        "family_index": index,
                        "verification_status": "deterministic_reference_generator",
                    },
                )
            )
    return tuple(records)


def _jsonl_payload(records: Iterable[Mapping[str, Any]]) -> bytes:
    return b"".join(canonical_json_bytes(record) + b"\n" for record in records)


def _partition_manifest(name: str, payload: bytes, records: tuple[dict[str, Any], ...]) -> dict[str, Any]:
    ordered_digests = [record["record_sha256"] for record in records]
    return {
        "path": TARGET_FILE_NAME if name == "target" else SUPPORT_FILE_NAME,
        "partition": name,
        "records": len(records),
        "bytes": len(payload),
        "sha256": sha256(payload).hexdigest(),
        "record_set_sha256": value_sha256(
            {
                "contract": "cbds.training-record-set",
                "version": "1.0.0",
                "partition": name,
                "record_sha256s": sorted(ordered_digests),
            }
        ),
        "record_sequence_sha256": value_sha256(
            {
                "contract": "cbds.training-record-sequence",
                "version": "1.0.0",
                "partition": name,
                "record_sha256s": ordered_digests,
            }
        ),
    }


def _manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(manifest, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")


def _write_new_file_at(directory_descriptor: int, name: str, payload: bytes) -> None:
    if not name or "/" in name or name in {".", ".."}:
        raise TrainingCorpusError("artifact member name is invalid")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    descriptor = os.open(name, flags, 0o644, dir_fd=directory_descriptor)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            os.unlink(name, dir_fd=directory_descriptor)
        except FileNotFoundError:
            pass
        raise


def _rename_directory_noreplace(
    parent_descriptor: int,
    source_name: str,
    destination_name: str,
) -> None:
    """Publish a staged directory atomically without replacing any inode."""

    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as exc:  # pragma: no cover - Linux/glibc requirement
        raise TrainingCorpusError("platform lacks renameat2") from exc
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent_descriptor,
        os.fsencode(source_name),
        parent_descriptor,
        os.fsencode(destination_name),
        1,  # RENAME_NOREPLACE
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        raise TrainingCorpusError("output directory already exists")
    raise TrainingCorpusError(
        f"cannot atomically publish corpus artifact: {os.strerror(error_number)}"
    )


def _cleanup_staging_directory(parent_descriptor: int, name: str) -> None:
    try:
        descriptor = os.open(name, _directory_open_flags(), dir_fd=parent_descriptor)
    except OSError:
        return
    try:
        for member in (
            TARGET_FILE_NAME,
            SUPPORT_FILE_NAME,
            MANIFEST_FILE_NAME,
            MANIFEST_SIDECAR_NAME,
        ):
            try:
                os.unlink(member, dir_fd=descriptor)
            except FileNotFoundError:
                pass
    finally:
        os.close(descriptor)
    try:
        os.rmdir(name, dir_fd=parent_descriptor)
    except OSError:
        pass


def prepare_training_corpus(
    config: object,
    *,
    source_root: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
) -> dict[str, Any]:
    """Prepare the pinned logical target/support corpus in a new directory."""

    validated = validate_training_corpus_config(config)
    source = Path(source_root)
    relative = validated["target_source"]["relative_path"]
    source_path = source.joinpath(*PurePosixPath(relative).parts)
    payload = _read_stable_source(source_path, maximum_bytes=MAX_SOURCE_BYTES)
    card_relative = validated["target_source"]["dataset_card_relative_path"]
    card_payload = _read_stable_source(
        source.joinpath(*PurePosixPath(card_relative).parts),
        maximum_bytes=4 * 1024 * 1024,
    )
    if sha256(card_payload).hexdigest() != validated["target_source"]["dataset_card_sha256"]:
        raise TrainingCorpusError("target dataset-card SHA-256 does not match the pinned config")
    target_records = _target_records(payload, validated)
    support_records = _support_records(validated)
    target_payload = _jsonl_payload(target_records)
    support_payload = _jsonl_payload(support_records)
    if len(target_payload) > MAX_PARTITION_BYTES or len(support_payload) > MAX_PARTITION_BYTES:
        raise TrainingCorpusError("prepared partition exceeds the byte ceiling")

    partition_records = [
        _partition_manifest("target", target_payload, target_records),
        _partition_manifest("support", support_payload, support_records),
    ]
    manifest_core: dict[str, Any] = {
        "schema_version": CORPUS_SCHEMA_VERSION,
        "record_type": "cbds.training-corpus-manifest",
        "corpus_id": validated["corpus_id"],
        "seed": validated["seed"],
        "preparer": _preparer_identity(),
        "config_sha256": value_sha256(validated),
        "formatting": validated["formatting"],
        "target_source": validated["target_source"],
        "support_source": validated["support_source"],
        "partitions": partition_records,
        "total_records": len(target_records) + len(support_records),
        "test_source_imported": False,
        "quality_scope": _QUALITY_SCOPE,
        "limitations": list(_LIMITATIONS),
        "corpus_hash_scope": "canonical_json_excluding_corpus_sha256",
    }
    manifest = dict(manifest_core)
    manifest["corpus_sha256"] = value_sha256(manifest_core)
    manifest_payload = _manifest_bytes(manifest)
    sidecar = f"{sha256(manifest_payload).hexdigest()}  {MANIFEST_FILE_NAME}\n".encode("ascii")

    destination = Path(output_dir)
    if destination.name in {"", ".", ".."}:
        raise TrainingCorpusError("output directory must have a safe final component")
    parent_descriptor = _open_directory_path(destination.parent, create=True)
    staging_name = ""
    staging_descriptor: int | None = None
    published = False
    try:
        for _ in range(128):
            candidate = f".{destination.name}.{os.urandom(16).hex()}.tmp"
            try:
                os.mkdir(candidate, mode=0o755, dir_fd=parent_descriptor)
            except FileExistsError:
                continue
            staging_name = candidate
            break
        if not staging_name:
            raise TrainingCorpusError("cannot allocate a unique staging directory")
        staging_descriptor = os.open(
            staging_name, _directory_open_flags(), dir_fd=parent_descriptor
        )
        _write_new_file_at(staging_descriptor, TARGET_FILE_NAME, target_payload)
        _write_new_file_at(staging_descriptor, SUPPORT_FILE_NAME, support_payload)
        _write_new_file_at(staging_descriptor, MANIFEST_FILE_NAME, manifest_payload)
        _write_new_file_at(staging_descriptor, MANIFEST_SIDECAR_NAME, sidecar)
        os.fsync(staging_descriptor)
        _rename_directory_noreplace(
            parent_descriptor, staging_name, destination.name
        )
        published = True
        os.fsync(parent_descriptor)
    except BaseException:
        raise
    finally:
        if staging_descriptor is not None:
            os.close(staging_descriptor)
        if staging_name and not published:
            _cleanup_staging_directory(parent_descriptor, staging_name)
        os.close(parent_descriptor)
    return {
        "schema_version": CORPUS_SCHEMA_VERSION,
        "corpus_id": manifest["corpus_id"],
        "corpus_sha256": manifest["corpus_sha256"],
        "manifest_sha256": sha256(manifest_payload).hexdigest(),
        "config_sha256": manifest["config_sha256"],
        "target_records": len(target_records),
        "support_records": len(support_records),
        "test_source_imported": False,
        "claim_authorized": False,
    }


def _duplicate_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TrainingCorpusError("record contains a duplicate JSON key")
        result[key] = value
    return result


def _validate_record(
    value: object,
    partition: str,
    config: Mapping[str, Any],
) -> dict[str, Any]:
    record = _exact_keys(value, _RECORD_KEYS, "record")
    if record["schema_version"] != RECORD_SCHEMA_VERSION:
        raise TrainingCorpusError("record schema version is invalid")
    if record["partition"] != partition:
        raise TrainingCorpusError("record partition disagrees with its file")
    record_id = _string(record["record_id"], "record.record_id")
    digest = _sha256(record["record_sha256"], "record.record_sha256")
    family = _string(record["family"], "record.family")
    prompt = _string(record["prompt"], "record.prompt")
    completion = _string(record["completion"], "record.completion")
    if _normalize_text(prompt) != prompt or _normalize_text(completion) != completion:
        raise TrainingCorpusError("record text is not LF-normalized")
    if len(prompt.encode("utf-8")) > MAX_PROMPT_UTF8_BYTES:
        raise TrainingCorpusError("record prompt exceeds the UTF-8 byte limit")
    if len(completion.encode("utf-8")) > MAX_COMPLETION_UTF8_BYTES:
        raise TrainingCorpusError("record completion exceeds the UTF-8 byte limit")
    source = record["source"]
    if partition == "target":
        source = _exact_keys(source, _TARGET_RECORD_SOURCE_KEYS, "target record.source")
        target = config["target_source"]
        if family != "nl2sh_single_line_unparsed":
            raise TrainingCorpusError("target record family is invalid")
        expected_source = {
            "repository": target["repository"],
            "revision": target["revision"],
            "split": "train",
            "relative_path": target["relative_path"],
            "file_sha256": target["file_sha256"],
            "verification_status": "unverified_upstream_pairs",
        }
        for key, expected in expected_source.items():
            if source[key] != expected:
                raise TrainingCorpusError(
                    f"target record source field {key!r} disagrees with the manifest"
                )
        row_number = source["row_number"]
        if (
            isinstance(row_number, bool)
            or not isinstance(row_number, int)
            or row_number < 2
            or row_number > target["expected_rows"] + 1
        ):
            raise TrainingCorpusError("target record source row_number is invalid")
    else:
        source = _exact_keys(source, _SUPPORT_RECORD_SOURCE_KEYS, "support record.source")
        support = config["support_source"]
        if family not in _SUPPORT_FAMILIES:
            raise TrainingCorpusError("support record family is invalid")
        expected_source = {
            "generator": support["generator"],
            "version": support["version"],
            "seed": support["seed"],
            "verification_status": "deterministic_reference_generator",
        }
        for key, expected in expected_source.items():
            if source[key] != expected:
                raise TrainingCorpusError(
                    f"support record source field {key!r} disagrees with the manifest"
                )
        family_index = source["family_index"]
        if (
            isinstance(family_index, bool)
            or not isinstance(family_index, int)
            or family_index < 0
            or family_index >= support["records_per_family"]
        ):
            raise TrainingCorpusError("support record family_index is invalid")
        expected_prompt, expected_completion = _support_example(
            family, family_index, support["seed"]
        )
        if prompt != expected_prompt or completion != expected_completion:
            raise TrainingCorpusError("support record does not reproduce from its generator")
    core = {
        "schema_version": RECORD_SCHEMA_VERSION,
        "partition": partition,
        "family": family,
        "prompt": prompt,
        "completion": completion,
        "source": source,
    }
    computed = value_sha256(core)
    if digest != computed or record_id != f"tr-{computed[:24]}":
        raise TrainingCorpusError("record content address does not verify")
    return json.loads(canonical_json_bytes(record))


def _read_regular_at(directory_descriptor: int, name: str, maximum: int) -> bytes:
    if not name or "/" in name or name in {".", ".."}:
        raise TrainingCorpusError("corpus artifact member name is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:  # pragma: no cover
        raise TrainingCorpusError("platform lacks O_NOFOLLOW")
    try:
        descriptor = os.open(name, flags | nofollow, dir_fd=directory_descriptor)
    except OSError as exc:
        raise TrainingCorpusError(f"cannot open corpus artifact: {type(exc).__name__}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise TrainingCorpusError("corpus artifact member is not a regular file")
        if before.st_size > maximum:
            raise TrainingCorpusError("corpus artifact member exceeds its byte limit")
        data = bytearray()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise TrainingCorpusError("corpus artifact ended early")
            data.extend(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise TrainingCorpusError("corpus artifact grew during read")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _fingerprint(before) != _fingerprint(after):
        raise TrainingCorpusError("corpus artifact changed during read")
    try:
        named = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise TrainingCorpusError(
            f"cannot recheck corpus artifact member: {type(exc).__name__}"
        ) from exc
    if _fingerprint(named) != _fingerprint(after):
        raise TrainingCorpusError("corpus artifact member path changed during read")
    return bytes(data)


def _validate_partition(
    root_descriptor: int,
    declaration: Mapping[str, Any],
    expected_partition: str,
    config: Mapping[str, Any],
) -> tuple[int, str, set[tuple[str, str]]]:
    expected_keys = frozenset(
        {
            "path",
            "partition",
            "records",
            "bytes",
            "sha256",
            "record_set_sha256",
            "record_sequence_sha256",
        }
    )
    item = _exact_keys(declaration, expected_keys, f"partition {expected_partition}")
    expected_path = TARGET_FILE_NAME if expected_partition == "target" else SUPPORT_FILE_NAME
    if item["path"] != expected_path or item["partition"] != expected_partition:
        raise TrainingCorpusError("partition declaration path or name is invalid")
    expected_records = _positive_int(
        item["records"], f"partition {expected_partition} records", maximum=MAX_RECORDS_PER_PARTITION
    )
    required_records = (
        config["target_source"]["expected_unique_pairs"]
        if expected_partition == "target"
        else config["support_source"]["records_per_family"] * len(_SUPPORT_FAMILIES)
    )
    if expected_records != required_records:
        raise TrainingCorpusError(
            f"partition {expected_partition} record count disagrees with its config"
        )
    expected_bytes = _positive_int(
        item["bytes"], f"partition {expected_partition} bytes", maximum=MAX_PARTITION_BYTES
    )
    expected_hash = _sha256(item["sha256"], f"partition {expected_partition} sha256")
    expected_set = _sha256(
        item["record_set_sha256"], f"partition {expected_partition} record_set_sha256"
    )
    expected_sequence = _sha256(
        item["record_sequence_sha256"],
        f"partition {expected_partition} record_sequence_sha256",
    )
    payload = _read_regular_at(root_descriptor, expected_path, MAX_PARTITION_BYTES)
    if len(payload) != expected_bytes or sha256(payload).hexdigest() != expected_hash:
        raise TrainingCorpusError(f"partition {expected_partition} file identity differs")
    if payload and not payload.endswith(b"\n"):
        raise TrainingCorpusError(f"partition {expected_partition} lacks final LF")
    ids: set[str] = set()
    digests: list[str] = []
    digest_set: set[str] = set()
    pairs: set[tuple[str, str]] = set()
    lines = payload.splitlines()
    if len(lines) != expected_records:
        raise TrainingCorpusError(f"partition {expected_partition} record count differs")
    previous_target_row = 1
    for ordinal, line in enumerate(lines):
        if not line or b"\r" in line:
            raise TrainingCorpusError("partition JSONL contains an empty line or CR")
        try:
            value = json.loads(
                line.decode("utf-8", errors="strict"),
                object_pairs_hook=_duplicate_object_pairs,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TrainingCorpusError("partition JSONL is not strict UTF-8 JSON") from exc
        record = _validate_record(value, expected_partition, config)
        if canonical_json_bytes(record) != line:
            raise TrainingCorpusError("partition record bytes are not canonical JSON")
        if expected_partition == "target":
            row_number = record["source"]["row_number"]
            if row_number <= previous_target_row:
                raise TrainingCorpusError("target source rows are not strictly increasing")
            previous_target_row = row_number
        else:
            records_per_family = config["support_source"]["records_per_family"]
            expected_family = _SUPPORT_FAMILIES[ordinal // records_per_family]
            expected_family_index = ordinal % records_per_family
            if (
                record["family"] != expected_family
                or record["source"]["family_index"] != expected_family_index
            ):
                raise TrainingCorpusError("support records are not in frozen generator order")
        if record["record_id"] in ids or record["record_sha256"] in digest_set:
            raise TrainingCorpusError("partition contains duplicate record identities")
        pair = (record["prompt"], record["completion"])
        if pair in pairs:
            raise TrainingCorpusError("partition contains duplicate prompt/completion pairs")
        ids.add(record["record_id"])
        digests.append(record["record_sha256"])
        digest_set.add(record["record_sha256"])
        pairs.add(pair)
    computed_set = value_sha256(
        {
            "contract": "cbds.training-record-set",
            "version": "1.0.0",
            "partition": expected_partition,
            "record_sha256s": sorted(digests),
        }
    )
    if computed_set != expected_set:
        raise TrainingCorpusError(f"partition {expected_partition} record-set hash differs")
    computed_sequence = value_sha256(
        {
            "contract": "cbds.training-record-sequence",
            "version": "1.0.0",
            "partition": expected_partition,
            "record_sha256s": digests,
        }
    )
    if computed_sequence != expected_sequence:
        raise TrainingCorpusError(
            f"partition {expected_partition} record-sequence hash differs"
        )
    return len(lines), expected_hash, pairs


def _validate_training_corpus_artifacts_open(
    root_descriptor: int,
    *,
    expected_corpus_sha256: str | None = None,
    expected_manifest_sha256: str | None = None,
    source_root: str | os.PathLike[str] | None = None,
    require_authenticated: bool = False,
) -> dict[str, Any]:
    try:
        names = set(os.listdir(root_descriptor))
    except OSError as exc:
        raise TrainingCorpusError(f"cannot inventory corpus root: {type(exc).__name__}") from exc
    if names != _CORPUS_MEMBER_NAMES:
        raise TrainingCorpusError("corpus root inventory is not exact")
    manifest_payload = _read_regular_at(
        root_descriptor, MANIFEST_FILE_NAME, 4 * 1024 * 1024
    )
    manifest_digest = sha256(manifest_payload).hexdigest()
    sidecar = _read_regular_at(root_descriptor, MANIFEST_SIDECAR_NAME, 1024)
    if sidecar != f"{manifest_digest}  {MANIFEST_FILE_NAME}\n".encode("ascii"):
        raise TrainingCorpusError("manifest sidecar does not verify")
    if expected_manifest_sha256 is not None:
        if _sha256(expected_manifest_sha256, "expected_manifest_sha256") != manifest_digest:
            raise TrainingCorpusError("manifest SHA-256 differs from the external pin")
    try:
        manifest = json.loads(
            manifest_payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_duplicate_object_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrainingCorpusError("manifest is not strict UTF-8 JSON") from exc
    if not isinstance(manifest, Mapping):
        raise TrainingCorpusError("manifest must be an object")
    required = {
        "schema_version",
        "record_type",
        "corpus_id",
        "seed",
        "preparer",
        "config_sha256",
        "formatting",
        "target_source",
        "support_source",
        "partitions",
        "total_records",
        "test_source_imported",
        "quality_scope",
        "limitations",
        "corpus_hash_scope",
        "corpus_sha256",
    }
    if set(manifest) != required:
        raise TrainingCorpusError("manifest keys are not exact")
    if _manifest_bytes(manifest) != manifest_payload:
        raise TrainingCorpusError("manifest bytes are not canonical pretty JSON")
    if manifest["schema_version"] != CORPUS_SCHEMA_VERSION:
        raise TrainingCorpusError("manifest schema version is invalid")
    if manifest["record_type"] != "cbds.training-corpus-manifest":
        raise TrainingCorpusError("manifest record type is invalid")
    if manifest["test_source_imported"] is not False:
        raise TrainingCorpusError("manifest must prove that the test source was not imported")
    _validate_preparer_identity(manifest["preparer"])
    if manifest["quality_scope"] != _QUALITY_SCOPE:
        raise TrainingCorpusError("training corpus cannot authorize a research claim")
    if manifest["limitations"] != list(_LIMITATIONS):
        raise TrainingCorpusError("manifest limitations do not equal the frozen claim boundary")
    reconstructed_config = {
        "schema_version": manifest["schema_version"],
        "corpus_id": manifest["corpus_id"],
        "seed": manifest["seed"],
        "target_source": manifest["target_source"],
        "support_source": manifest["support_source"],
        "formatting": manifest["formatting"],
    }
    validated_config = validate_training_corpus_config(reconstructed_config)
    declared_config = _sha256(manifest["config_sha256"], "manifest.config_sha256")
    if value_sha256(validated_config) != declared_config:
        raise TrainingCorpusError("manifest config SHA-256 does not reproduce")
    partitions = manifest["partitions"]
    if not isinstance(partitions, list) or len(partitions) != 2:
        raise TrainingCorpusError("manifest must contain exactly two partitions")
    by_name = {
        item.get("partition"): item for item in partitions if isinstance(item, Mapping)
    }
    if set(by_name) != {"target", "support"}:
        raise TrainingCorpusError("manifest partition names are invalid")
    if [item.get("partition") for item in partitions] != ["target", "support"]:
        raise TrainingCorpusError("manifest partitions are not in frozen order")
    target_count, target_hash, target_pairs = _validate_partition(
        root_descriptor, by_name["target"], "target", validated_config
    )
    support_count, support_hash, support_pairs = _validate_partition(
        root_descriptor, by_name["support"], "support", validated_config
    )
    if target_pairs.intersection(support_pairs):
        raise TrainingCorpusError("target and support partitions share a prompt/completion pair")
    declared_total = _positive_int(
        manifest["total_records"],
        "manifest.total_records",
        maximum=2 * MAX_RECORDS_PER_PARTITION,
    )
    if declared_total != target_count + support_count:
        raise TrainingCorpusError("manifest total_records does not reproduce")
    declared_corpus = _sha256(manifest["corpus_sha256"], "manifest.corpus_sha256")
    if manifest["corpus_hash_scope"] != "canonical_json_excluding_corpus_sha256":
        raise TrainingCorpusError("manifest corpus hash scope is invalid")
    unsigned = dict(manifest)
    unsigned.pop("corpus_sha256")
    if value_sha256(unsigned) != declared_corpus:
        raise TrainingCorpusError("manifest corpus SHA-256 does not reproduce")
    if expected_corpus_sha256 is not None:
        if _sha256(expected_corpus_sha256, "expected_corpus_sha256") != declared_corpus:
            raise TrainingCorpusError("corpus SHA-256 differs from the external pin")
    source_replay_verified = False
    if source_root is not None:
        replay_root = Path(source_root)
        target_source = validated_config["target_source"]
        replay_target = _read_stable_source(
            replay_root.joinpath(*PurePosixPath(target_source["relative_path"]).parts),
            maximum_bytes=MAX_SOURCE_BYTES,
        )
        replay_card = _read_stable_source(
            replay_root.joinpath(
                *PurePosixPath(target_source["dataset_card_relative_path"]).parts
            ),
            maximum_bytes=4 * 1024 * 1024,
        )
        if sha256(replay_card).hexdigest() != target_source["dataset_card_sha256"]:
            raise TrainingCorpusError(
                "source replay dataset-card SHA-256 differs from the manifest"
            )
        replay_target_payload = _jsonl_payload(
            _target_records(replay_target, validated_config)
        )
        replay_support_payload = _jsonl_payload(_support_records(validated_config))
        if replay_target_payload != _read_regular_at(
            root_descriptor, TARGET_FILE_NAME, MAX_PARTITION_BYTES
        ):
            raise TrainingCorpusError(
                "target partition does not reproduce byte-for-byte from the pinned source"
            )
        if replay_support_payload != _read_regular_at(
            root_descriptor, SUPPORT_FILE_NAME, MAX_PARTITION_BYTES
        ):
            raise TrainingCorpusError(
                "support partition does not reproduce byte-for-byte from its generator"
            )
        source_replay_verified = True
    external_pin_verified = (
        expected_corpus_sha256 is not None or expected_manifest_sha256 is not None
    )
    authenticated = external_pin_verified or source_replay_verified
    if require_authenticated and not authenticated:
        raise TrainingCorpusError(
            "authenticated corpus identity requires an external hash pin or source replay"
        )
    return {
        "schema_version": CORPUS_SCHEMA_VERSION,
        "valid": True,
        "corpus_id": manifest["corpus_id"],
        "corpus_sha256": declared_corpus,
        "manifest_sha256": manifest_digest,
        "config_sha256": manifest["config_sha256"],
        "target_records": target_count,
        "support_records": support_count,
        "target_file_sha256": target_hash,
        "support_file_sha256": support_hash,
        "test_source_imported": False,
        "authenticated": authenticated,
        "authentication": {
            "external_pin_verified": external_pin_verified,
            "source_replay_verified": source_replay_verified,
        },
        "claim_authorized": False,
    }


def validate_training_corpus_artifacts(
    source: str | os.PathLike[str],
    *,
    expected_corpus_sha256: str | None = None,
    expected_manifest_sha256: str | None = None,
    source_root: str | os.PathLike[str] | None = None,
    require_authenticated: bool = False,
) -> dict[str, Any]:
    """Inspect a corpus and optionally authenticate it against trusted bytes.

    Internal consistency alone cannot authenticate target rows: an attacker
    could replace a row and recompute every nested digest.  Authentication
    therefore requires at least one caller-supplied external artifact pin or a
    byte-for-byte replay from the pinned raw source.  Training callers should
    set ``require_authenticated=True`` and bind both external hashes.
    """

    if not isinstance(require_authenticated, bool):
        raise TrainingCorpusError("require_authenticated must be a boolean")
    root = Path(source)
    root_descriptor = _open_directory_path(root, create=False)
    before = os.fstat(root_descriptor)
    try:
        result = _validate_training_corpus_artifacts_open(
            root_descriptor,
            expected_corpus_sha256=expected_corpus_sha256,
            expected_manifest_sha256=expected_manifest_sha256,
            source_root=source_root,
            require_authenticated=require_authenticated,
        )
        if set(os.listdir(root_descriptor)) != _CORPUS_MEMBER_NAMES:
            raise TrainingCorpusError("corpus root inventory changed during verification")
        after = os.fstat(root_descriptor)
        if _fingerprint(before) != _fingerprint(after):
            raise TrainingCorpusError("corpus root changed during verification")
        reopened = _open_directory_path(root, create=False)
        try:
            current = os.fstat(reopened)
            if current.st_dev != after.st_dev or current.st_ino != after.st_ino:
                raise TrainingCorpusError("corpus root path changed during verification")
        finally:
            os.close(reopened)
        return result
    finally:
        os.close(root_descriptor)


def load_training_corpus_config(path: str | os.PathLike[str]) -> dict[str, Any]:
    return validate_training_corpus_config(load_document(path))


__all__ = [
    "CORPUS_PREPARER_VERSION",
    "CORPUS_SCHEMA_VERSION",
    "RECORD_SCHEMA_VERSION",
    "SUPPORT_GENERATOR_VERSION",
    "TrainingCorpusError",
    "load_training_corpus_config",
    "prepare_training_corpus",
    "training_corpus_config_sha256",
    "validate_training_corpus_artifacts",
    "validate_training_corpus_config",
]
