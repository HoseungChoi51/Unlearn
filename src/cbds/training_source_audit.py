"""Authenticated, non-promoting lexical audit of raw terminal training rows.

This module is intentionally a *source-audit* gate, not a corpus curator.  It
reads a logical training corpus only after both caller-supplied artifact hashes
and byte-for-byte raw-source replay have verified.  Source commands are treated
as inert text: this module imports no command runner and never parses by asking
a shell to evaluate or execute them.

Rows that survive the conservative lexical checks are called
``static_candidate`` records.  That label means only that no known lexical
rejection fired and every lexically observed command name is in the frozen
positive allowlist.  It does not mean that the command is valid Bash, safe,
functionally correct, target-policy accepted, or eligible for training.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
import ctypes
from dataclasses import dataclass
import errno
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import stat
import unicodedata
from typing import Any, Final

from . import manifests as manifests_module
from . import training_corpus as training_corpus_module
from .manifests import canonical_json_bytes, value_sha256
from .training_corpus import TrainingCorpusError, validate_training_corpus_artifacts


AUDIT_SCHEMA_VERSION: Final[str] = "1.0.0"
AUDIT_PREPARER_VERSION: Final[str] = "1.0.0"
CLASSIFIER_VERSION: Final[str] = "1.0.0"
CANDIDATE_FILE_NAME: Final[str] = "accepted-candidates.jsonl"
REJECTION_FILE_NAME: Final[str] = "rejections.jsonl"
MANIFEST_FILE_NAME: Final[str] = "manifest.json"
MANIFEST_SIDECAR_NAME: Final[str] = "manifest.sha256"
MAX_TARGET_BYTES: Final[int] = 256 * 1024 * 1024
MAX_LEDGER_BYTES: Final[int] = 256 * 1024 * 1024
MAX_MANIFEST_BYTES: Final[int] = 8 * 1024 * 1024
MAX_RECORDS: Final[int] = 100_000

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_ID_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9._-]{2,127}\Z")
_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:\+)?=.*\Z", re.DOTALL
)
_NON_SHELL_UI_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?:"
    r"<(?:enter|return|space(?:bar)?|tab|esc(?:ape)?|backspace|delete|"
    r"up|down|left|right|home|end|pageup|pagedown|f\d{1,2})>"
    r"|(?:ctrl|control|alt|option|cmd|command|shift)\s*[+-]\s*[A-Za-z0-9]"
    r"|\[(?:arrow\s+)?(?:up|down|left|right)\]"
    r")"
)
_PLACEHOLDER_PATTERNS: Final[tuple[str, ...]] = (
    r"(?i)(?:^|[\s=:'\"])(?:/?path/to|/?folder/to|/?directory/to)(?:/|\b)",
    r"(?i)<(?:path|file|folder|directory|command|argument|value|name|host|port)>",
    r"(?i)\b(?:command|subcommand|package|username|hostname|filename|foldername)(?:_[0-9]+|[0-9]+)\b",
    r"\{\{[^{}]+\}\}",
    r"(?:^|\s)\.\.\.(?:\s|$)",
)
_PLACEHOLDER_RES: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(pattern) for pattern in _PLACEHOLDER_PATTERNS
)
_DEVICE_PATH_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:^|[\s=:,'\"])/dev(?:/|\b)"
)
_ABSOLUTE_SYSTEM_PATH_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:^|[\s=:,'\"])/(?:bin|boot|etc|home|lib(?:32|64)?|opt|proc|root|"
    r"run|sbin|srv|sys|usr|var)(?:/|\b)"
)

# This is a deliberately positive list for the project's primary offline Unix
# target.  Absence is a rejection; presence is not an acceptance claim.
_POSITIVE_EXECUTABLE_ALLOWLIST: Final[frozenset[str]] = frozenset(
    {
        ":",
        "[",
        "arch",
        "awk",
        "base32",
        "base64",
        "basename",
        "basenc",
        "bzip2",
        "bzcat",
        "cat",
        "cd",
        "chgrp",
        "chmod",
        "chown",
        "cksum",
        "cmp",
        "comm",
        "cp",
        "csplit",
        "cut",
        "date",
        "dd",
        "df",
        "diff",
        "diff3",
        "dir",
        "dircolors",
        "dirname",
        "du",
        "echo",
        "expand",
        "expr",
        "factor",
        "false",
        "find",
        "fmt",
        "fold",
        "gawk",
        "getconf",
        "getent",
        "getopts",
        "grep",
        "groups",
        "gunzip",
        "gzip",
        "head",
        "hostid",
        "id",
        "join",
        "jq",
        "kill",
        "link",
        "ln",
        "local",
        "logname",
        "ls",
        "mapfile",
        "md5sum",
        "mkdir",
        "mkfifo",
        "mknod",
        "mktemp",
        "mv",
        "nice",
        "nl",
        "nohup",
        "nproc",
        "numfmt",
        "od",
        "paste",
        "patch",
        "pathchk",
        "pgrep",
        "pkill",
        "pr",
        "printenv",
        "printf",
        "ps",
        "pwd",
        "python3",
        "read",
        "readarray",
        "readlink",
        "realpath",
        "renice",
        "rev",
        "rm",
        "rmdir",
        "sed",
        "seq",
        "sha1sum",
        "sha224sum",
        "sha256sum",
        "sha384sum",
        "sha512sum",
        "shift",
        "shuf",
        "sleep",
        "sort",
        "split",
        "stat",
        "stdbuf",
        "sum",
        "sync",
        "tac",
        "tail",
        "tar",
        "tee",
        "test",
        "timeout",
        "touch",
        "tr",
        "true",
        "truncate",
        "tsort",
        "tty",
        "umask",
        "uname",
        "unexpand",
        "uniq",
        "unlink",
        "unxz",
        "unzip",
        "users",
        "vdir",
        "wait",
        "wc",
        "who",
        "whoami",
        "xargs",
        "xz",
        "xzcat",
        "yes",
        "zip",
        "zcat",
    }
)
_DYNAMIC_COMMANDS: Final[frozenset[str]] = frozenset(
    {
        "command",
        "env",
        "eval",
        "exec",
        "nice",
        "nohup",
        "parallel",
        "source",
        "stdbuf",
        "timeout",
        "xargs",
        ".",
    }
)
_SHELL_WRAPPERS: Final[frozenset[str]] = frozenset(
    {"ash", "bash", "csh", "dash", "fish", "ksh", "sh", "tcsh", "zsh"}
)
_CONTROL_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "!",
        "case",
        "coproc",
        "do",
        "done",
        "elif",
        "else",
        "esac",
        "fi",
        "for",
        "function",
        "if",
        "in",
        "select",
        "then",
        "time",
        "until",
        "while",
    }
)
_REDIRECTION_OPERATORS: Final[frozenset[str]] = frozenset(
    {"<", ">", ">>", "<>", ">&", "<&", "&>", "&>>", ">|"}
)
_UNSUPPORTED_REDIRECTION_OPERATORS: Final[frozenset[str]] = frozenset(
    {"<<", "<<-", "<<<"}
)
_COMMAND_BREAKS: Final[frozenset[str]] = frozenset({";", "&&", "||", "|"})
_OPERATORS: Final[tuple[str, ...]] = tuple(
    sorted(
        {
            ";;&",
            "&>>",
            "<<<",
            "<<-",
            "&&",
            "||",
            ";;",
            ";&",
            "|&",
            "<<",
            ">>",
            "<>",
            ">&",
            "<&",
            "&>",
            ">|",
            ";",
            "|",
            "&",
            "<",
            ">",
            "(",
            ")",
            "{",
            "}",
        },
        key=lambda value: (-len(value), value),
    )
)
_REASON_ORDER: Final[tuple[str, ...]] = (
    "ambiguous_normalized_prompt",
    "non_shell_ui_label",
    "placeholder_or_template",
    "command_substitution",
    "process_substitution",
    "dynamic_shell_expansion",
    "dynamic_execution",
    "eval_or_source",
    "shell_wrapper",
    "absolute_device_path",
    "absolute_system_path",
    "unsupported_shell_structure",
    "unsupported_redirection",
    "lexical_parse_failed",
    "no_executable_utility",
    "utility_not_allowlisted",
)
_REASON_RANK: Final[dict[str, int]] = {
    reason: index for index, reason in enumerate(_REASON_ORDER)
}
_EVALUATION_BINDING_KEYS: Final[frozenset[str]] = frozenset(
    {
        "operator_selection_manifest_sha256",
        "method_development_manifest_sha256",
        "shadow_validation_manifest_sha256",
        "sealed_static_commitment_sha256",
        "bounded_terminal_development_manifest_sha256",
    }
)
_QUALITY_SCOPE: Final[dict[str, object]] = {
    "classification_scope": "stdlib_lexical_prefilter_only",
    "ast_parsed": False,
    "execution_verified": False,
    "training_eligible": False,
    "target_policy_accepted": False,
    "claim_authorized": False,
}
_LIMITATIONS: Final[tuple[str, ...]] = (
    "Accepted candidates passed only a conservative standard-library lexical prefilter.",
    "No Bash AST parser, syntax checker, static analyzer, shell, command, or fixture was executed.",
    "Lexical utility extraction can have both false positives and false negatives.",
    "Rejected plaintext is intentionally absent from the rejection ledger.",
    "Record hashes are provenance commitments, not confidentiality guarantees for low-entropy source text.",
    "Evaluation hashes are binding slots only; prompt, AST, graph, and trace leakage have not been measured.",
    "No row is training eligible, target-policy accepted, execution verified, or claim authorizing.",
)


class TrainingSourceAuditError(ValueError):
    """Fail-closed source-audit preparation or validation error."""

    def __init__(self, issues: str | Iterable[str]) -> None:
        normalized = (issues,) if isinstance(issues, str) else tuple(issues)
        if not normalized:
            normalized = ("training source audit failed",)
        self.issues = tuple(str(item) for item in normalized)
        super().__init__("training source audit failed:\n- " + "\n- ".join(self.issues))


@dataclass(frozen=True)
class _Lexeme:
    kind: str
    value: str
    quoted: bool


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise TrainingSourceAuditError(f"{label} must be a lowercase SHA-256")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise TrainingSourceAuditError(f"{label} must be a canonical identifier")
    return value


def _exact_keys(value: object, keys: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TrainingSourceAuditError(f"{label} must be an object")
    if set(value) != keys:
        raise TrainingSourceAuditError(f"{label} keys are not exact")
    return value


def _reason_sort(reasons: Iterable[str]) -> list[str]:
    unique = set(reasons)
    unknown = unique.difference(_REASON_RANK)
    if unknown:
        raise TrainingSourceAuditError(f"unknown reason codes: {sorted(unknown)!r}")
    return sorted(unique, key=_REASON_RANK.__getitem__)


def normalize_prompt_for_collision(prompt: str) -> str:
    """Return the frozen comparison form used only for collision detection."""

    if not isinstance(prompt, str) or not prompt or "\x00" in prompt:
        raise TrainingSourceAuditError("prompt must be a nonempty NUL-free string")
    normalized = unicodedata.normalize("NFKC", prompt).casefold()
    return " ".join(normalized.split())


def _prompt_digest(normalized_prompt: str) -> str:
    return value_sha256(
        {
            "contract": "cbds.normalized-training-prompt",
            "version": "1.0.0",
            "normalization": "NFKC_casefold_unicode_whitespace_to_ascii_space_strip",
            "text": normalized_prompt,
        }
    )


def _completion_digest(completion: str) -> str:
    return value_sha256(
        {
            "contract": "cbds.raw-training-completion",
            "version": "1.0.0",
            "text": completion,
        }
    )


def _emit_word(tokens: list[_Lexeme], buffer: list[str], quoted: bool) -> bool:
    if buffer:
        tokens.append(_Lexeme("word", "".join(buffer), quoted))
        buffer.clear()
    return False


def _scan_shell_lexically(command: str) -> tuple[list[_Lexeme], set[str]]:
    tokens: list[_Lexeme] = []
    reasons: set[str] = set()
    buffer: list[str] = []
    token_quoted = False
    state = "plain"
    offset = 0
    while offset < len(command):
        character = command[offset]
        if state == "single":
            if character == "'":
                state = "plain"
            else:
                buffer.append(character)
            offset += 1
            continue
        if state == "double":
            if character == '"':
                state = "plain"
                offset += 1
                continue
            if character == "\\":
                if offset + 1 >= len(command):
                    reasons.add("lexical_parse_failed")
                    offset += 1
                else:
                    buffer.append(command[offset + 1])
                    offset += 2
                continue
            if character == "`":
                reasons.add("command_substitution")
            if character == "$" and offset + 1 < len(command) and command[offset + 1] == "(":
                if offset + 2 < len(command) and command[offset + 2] == "(":
                    reasons.add("dynamic_shell_expansion")
                else:
                    reasons.add("command_substitution")
            buffer.append(character)
            offset += 1
            continue

        if character.isspace():
            token_quoted = _emit_word(tokens, buffer, token_quoted)
            offset += 1
            continue
        if character == "#" and not buffer:
            break
        if character == "'":
            state = "single"
            token_quoted = True
            offset += 1
            continue
        if character == '"':
            state = "double"
            token_quoted = True
            offset += 1
            continue
        if character == "\\":
            if offset + 1 >= len(command):
                reasons.add("lexical_parse_failed")
                offset += 1
            else:
                buffer.append(command[offset + 1])
                offset += 2
            continue
        if character == "`":
            reasons.add("command_substitution")
            buffer.append(character)
            offset += 1
            continue
        if character == "$" and offset + 1 < len(command) and command[offset + 1] == "(":
            if offset + 2 < len(command) and command[offset + 2] == "(":
                reasons.add("dynamic_shell_expansion")
            else:
                reasons.add("command_substitution")
            buffer.append("$(")
            offset += 2
            continue
        if character in "<>" and offset + 1 < len(command) and command[offset + 1] == "(":
            reasons.add("process_substitution")
        operator = next(
            (candidate for candidate in _OPERATORS if command.startswith(candidate, offset)),
            None,
        )
        if operator is not None:
            token_quoted = _emit_word(tokens, buffer, token_quoted)
            tokens.append(_Lexeme("operator", operator, False))
            offset += len(operator)
            continue
        buffer.append(character)
        offset += 1
    if state != "plain":
        reasons.add("lexical_parse_failed")
    _emit_word(tokens, buffer, token_quoted)
    return tokens, reasons


def _extract_utilities(tokens: list[_Lexeme], reasons: set[str]) -> list[str]:
    utilities: list[str] = []
    command_start = True
    skip_redirection_operand = False
    current_utility: str | None = None
    command_required = False
    for token in tokens:
        if token.kind == "operator":
            operator = token.value
            if skip_redirection_operand:
                reasons.add("lexical_parse_failed")
                skip_redirection_operand = False
            if (
                command_required
                and operator not in _REDIRECTION_OPERATORS
                and operator not in _UNSUPPORTED_REDIRECTION_OPERATORS
            ):
                reasons.add("lexical_parse_failed")
            if operator in _UNSUPPORTED_REDIRECTION_OPERATORS:
                reasons.add("unsupported_redirection")
                skip_redirection_operand = True
            elif operator in _REDIRECTION_OPERATORS:
                skip_redirection_operand = True
            elif operator in _COMMAND_BREAKS:
                if command_start and operator != ";":
                    reasons.add("lexical_parse_failed")
                command_start = True
                current_utility = None
                command_required = operator in {"&&", "||", "|"}
            elif operator in {"&", "|&", "(", ")", "{", "}", ";;", ";&", ";;&"}:
                reasons.add("unsupported_shell_structure")
                command_start = operator in {"&", "|&", ";;", ";&", ";;&"}
                current_utility = None if command_start else current_utility
                command_required = operator == "|&"
            continue
        word = token.value
        if skip_redirection_operand:
            skip_redirection_operand = False
            continue
        if command_start:
            if _ASSIGNMENT_RE.fullmatch(word):
                continue
            if word in _CONTROL_KEYWORDS:
                reasons.add("unsupported_shell_structure")
                continue
            utility = word.rsplit("/", 1)[-1]
            if "/" in word:
                # PATH resolution is part of the later pinned execution policy.
                # An explicit path can point to arbitrary code despite ending
                # in an allowlisted basename such as ``ls``.
                reasons.add("dynamic_execution")
            if not utility or utility.startswith("$"):
                reasons.add("dynamic_execution")
                continue
            utilities.append(utility)
            current_utility = utility
            command_start = False
            command_required = False
            if utility in {"eval", "source", "."}:
                reasons.add("eval_or_source")
            elif utility in _DYNAMIC_COMMANDS:
                reasons.add("dynamic_execution")
            if utility in _SHELL_WRAPPERS:
                reasons.add("shell_wrapper")
            continue
        if current_utility == "find" and word in {"-exec", "-execdir", "-ok", "-okdir"}:
            reasons.add("dynamic_execution")
        if current_utility in {"python", "python3"} and word in {"-c", "-m"}:
            reasons.add("dynamic_execution")
    if skip_redirection_operand or command_required:
        reasons.add("lexical_parse_failed")
    return utilities


def _detect_embedded_execution(tokens: list[_Lexeme], utilities: list[str]) -> bool:
    """Detect known execution escape hatches inside otherwise allowed tools."""

    words = [token.value for token in tokens if token.kind == "word"]
    programs = "\n".join(words)
    if any(utility in {"awk", "gawk"} for utility in utilities):
        if re.search(r"(?i)\bsystem\s*\(", programs) or re.search(
            r"(?i)\|\s*getline\b", programs
        ):
            return True
    if "sed" in utilities and any(
        re.search(r"(?:^|[;{}])\s*e(?:\s|$)", word) is not None
        or re.search(r"^s(.).*\1[A-Za-z]*e[A-Za-z]*$", word) is not None
        for word in words
    ):
        return True
    if "tar" in utilities and any(
        word == "-I"
        or word.startswith("--checkpoint-action=exec")
        or word.startswith("--to-command=")
        or word.startswith("--use-compress-program=")
        for word in words
    ):
        return True
    if "sort" in utilities and any(
        word.startswith("--compress-program=") for word in words
    ):
        return True
    return False


def classifier_policy() -> dict[str, Any]:
    """Return the complete frozen lexical policy as canonical JSON data."""

    policy = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "classifier": "cbds.stdlib_conservative_shell_lexer",
        "version": CLASSIFIER_VERSION,
        "prompt_normalization": "NFKC_casefold_unicode_whitespace_to_ascii_space_strip",
        "positive_executable_allowlist": sorted(_POSITIVE_EXECUTABLE_ALLOWLIST),
        "dynamic_commands": sorted(_DYNAMIC_COMMANDS),
        "shell_wrappers": sorted(_SHELL_WRAPPERS),
        "embedded_execution_checks": [
            "awk_or_gawk_system_call_or_pipe_getline",
            "sed_e_command_or_substitution_e_flag",
            "sort_compress_program",
            "tar_checkpoint_to_command_or_compress_program",
        ],
        "absolute_system_roots": [
            "/bin",
            "/boot",
            "/etc",
            "/home",
            "/lib",
            "/lib32",
            "/lib64",
            "/opt",
            "/proc",
            "/root",
            "/run",
            "/sbin",
            "/srv",
            "/sys",
            "/usr",
            "/var",
        ],
        "device_root": "/dev",
        "placeholder_patterns": list(_PLACEHOLDER_PATTERNS),
        "reason_code_order": list(_REASON_ORDER),
        "classification_contract": {
            "survivor_label": "static_candidate",
            "ast_parsed": False,
            "execution_verified": False,
            "training_eligible": False,
            "target_policy_accepted": False,
            "claim_authorized": False,
        },
    }
    return json.loads(canonical_json_bytes(policy))


@lru_cache(maxsize=1)
def _classifier_policy_sha256() -> str:
    return value_sha256(classifier_policy())


def classify_target_command_lexically(
    command: str, *, ambiguous_normalized_prompt: bool = False
) -> dict[str, Any]:
    """Classify inert command text without invoking any executable or parser."""

    if not isinstance(command, str) or not command or "\x00" in command:
        raise TrainingSourceAuditError("command must be a nonempty NUL-free string")
    if not isinstance(ambiguous_normalized_prompt, bool):
        raise TrainingSourceAuditError("ambiguous_normalized_prompt must be boolean")
    reasons: set[str] = set()
    if ambiguous_normalized_prompt:
        reasons.add("ambiguous_normalized_prompt")
    if "\n" in command or "\r" in command:
        reasons.add("lexical_parse_failed")
    tokens, scan_reasons = _scan_shell_lexically(command)
    reasons.update(scan_reasons)
    # Scan both the exact source and quote-concatenated lexical words.  The
    # latter prevents constructions such as /'etc'/passwd or e"va"l from
    # evading path/utility checks merely by splitting a token across quotes.
    lexical_words = " ".join(token.value for token in tokens if token.kind == "word")
    for inspected in (command, lexical_words):
        if _NON_SHELL_UI_RE.search(inspected):
            reasons.add("non_shell_ui_label")
        if any(pattern.search(inspected) for pattern in _PLACEHOLDER_RES):
            reasons.add("placeholder_or_template")
        if _DEVICE_PATH_RE.search(inspected):
            reasons.add("absolute_device_path")
        if _ABSOLUTE_SYSTEM_PATH_RE.search(inspected):
            reasons.add("absolute_system_path")
    # Wrapper commands can appear behind allowlisted launch prefixes such as
    # ``timeout`` or ``nohup``.  Looking at all lexical words is conservative
    # (and can reject a literal argument named "bash"), which is appropriate
    # for a candidate-only prefilter.
    if any(
        token.kind == "word" and token.value.rsplit("/", 1)[-1] in _SHELL_WRAPPERS
        for token in tokens
    ):
        reasons.add("shell_wrapper")
    utilities = _extract_utilities(tokens, reasons)
    if _detect_embedded_execution(tokens, utilities):
        reasons.add("dynamic_execution")
    if not utilities:
        reasons.add("no_executable_utility")
    if any(utility not in _POSITIVE_EXECUTABLE_ALLOWLIST for utility in utilities):
        reasons.add("utility_not_allowlisted")
    ordered_reasons = _reason_sort(reasons)
    status = "static_candidate" if not ordered_reasons else "rejected"
    result = {
        "classifier": "cbds.stdlib_conservative_shell_lexer",
        "classifier_version": CLASSIFIER_VERSION,
        "classifier_policy_sha256": _classifier_policy_sha256(),
        "status": status,
        "observed_utilities": utilities,
        "reason_codes": ordered_reasons,
        "ast_parsed": False,
        "execution_verified": False,
        "training_eligible": False,
        "target_policy_accepted": False,
        "claim_authorized": False,
    }
    return json.loads(canonical_json_bytes(result))


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


def _read_regular(path: Path, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:  # pragma: no cover - Linux experiment requirement
        raise TrainingSourceAuditError("platform lacks O_NOFOLLOW")
    try:
        descriptor = os.open(path, flags | nofollow)
    except OSError as exc:
        raise TrainingSourceAuditError(f"cannot open {label}: {type(exc).__name__}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise TrainingSourceAuditError(f"{label} must be a regular file")
        if before.st_size > maximum:
            raise TrainingSourceAuditError(f"{label} exceeds its byte limit")
        payload = bytearray()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise TrainingSourceAuditError(f"{label} ended early")
            payload.extend(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise TrainingSourceAuditError(f"{label} grew while being read")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _fingerprint(before) != _fingerprint(after):
        raise TrainingSourceAuditError(f"{label} changed while being read")
    return bytes(payload)


def _directory_open_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", None)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if directory is None or nofollow is None:  # pragma: no cover - Linux requirement
        raise TrainingSourceAuditError("platform lacks O_DIRECTORY or O_NOFOLLOW")
    return os.O_RDONLY | os.O_CLOEXEC | directory | nofollow


def _open_directory_path(path: Path, *, create: bool) -> int:
    """Open every directory component without following a symlink."""

    absolute = Path(os.path.abspath(path))
    descriptor = os.open("/", _directory_open_flags())
    try:
        for part in absolute.parts[1:]:
            if part in {"", ".", ".."}:
                raise TrainingSourceAuditError("directory path is not canonical")
            if create:
                try:
                    os.mkdir(part, mode=0o755, dir_fd=descriptor)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise TrainingSourceAuditError(
                        f"cannot create output parent: {type(exc).__name__}"
                    ) from exc
            try:
                child = os.open(part, _directory_open_flags(), dir_fd=descriptor)
                named = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                opened = os.fstat(child)
            except OSError as exc:
                raise TrainingSourceAuditError(
                    f"cannot open directory path: {type(exc).__name__}"
                ) from exc
            if (
                named.st_dev != opened.st_dev
                or named.st_ino != opened.st_ino
                or not stat.S_ISDIR(named.st_mode)
            ):
                os.close(child)
                raise TrainingSourceAuditError("directory component changed while opening")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_regular_at(directory_descriptor: int, name: str, maximum: int, label: str) -> bytes:
    if not name or "/" in name or name in {".", ".."}:
        raise TrainingSourceAuditError("artifact member name is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:  # pragma: no cover
        raise TrainingSourceAuditError("platform lacks O_NOFOLLOW")
    try:
        descriptor = os.open(name, flags | nofollow, dir_fd=directory_descriptor)
    except OSError as exc:
        raise TrainingSourceAuditError(f"cannot open {label}: {type(exc).__name__}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise TrainingSourceAuditError(f"{label} must be a regular file")
        if before.st_size > maximum:
            raise TrainingSourceAuditError(f"{label} exceeds its byte limit")
        payload = bytearray()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise TrainingSourceAuditError(f"{label} ended early")
            payload.extend(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise TrainingSourceAuditError(f"{label} grew while being read")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _fingerprint(before) != _fingerprint(after):
        raise TrainingSourceAuditError(f"{label} changed while being read")
    try:
        named = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise TrainingSourceAuditError(f"cannot recheck {label}: {type(exc).__name__}") from exc
    if _fingerprint(named) != _fingerprint(after):
        raise TrainingSourceAuditError(f"{label} path changed while being read")
    return bytes(payload)


def _duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TrainingSourceAuditError("JSON contains a duplicate object key")
        result[key] = value
    return result


def _strict_json(payload: bytes, label: str) -> Any:
    try:
        return json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_duplicate_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                TrainingSourceAuditError(f"{label} contains non-finite number {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrainingSourceAuditError(f"{label} is not strict UTF-8 JSON") from exc


def _read_raw_target_records(corpus_dir: Path, expected_sha256: str) -> tuple[dict[str, Any], ...]:
    payload = _read_regular(corpus_dir / "target.jsonl", MAX_TARGET_BYTES, "raw target")
    if sha256(payload).hexdigest() != expected_sha256:
        raise TrainingSourceAuditError("raw target file differs from authenticated identity")
    if not payload or not payload.endswith(b"\n"):
        raise TrainingSourceAuditError("raw target JSONL must be nonempty and LF-terminated")
    records: list[dict[str, Any]] = []
    for line in payload.splitlines():
        value = _strict_json(line, "raw target record")
        if not isinstance(value, Mapping):
            raise TrainingSourceAuditError("raw target record must be an object")
        required = {
            "schema_version",
            "record_id",
            "record_sha256",
            "partition",
            "family",
            "prompt",
            "completion",
            "source",
        }
        if set(value) != required or value.get("partition") != "target":
            raise TrainingSourceAuditError("raw target record schema is invalid")
        if canonical_json_bytes(value) != line:
            raise TrainingSourceAuditError("raw target record is not canonical JSON")
        _identifier(value["record_id"], "raw target record_id")
        _sha(value["record_sha256"], "raw target record_sha256")
        if not isinstance(value["prompt"], str) or not isinstance(value["completion"], str):
            raise TrainingSourceAuditError("raw target text fields must be strings")
        records.append(json.loads(canonical_json_bytes(value)))
    if not records or len(records) > MAX_RECORDS:
        raise TrainingSourceAuditError("raw target record count is outside limits")
    return tuple(records)


def _load_raw_manifest(corpus_dir: Path, expected_sha256: str) -> dict[str, Any]:
    payload = _read_regular(corpus_dir / "manifest.json", MAX_MANIFEST_BYTES, "raw manifest")
    if sha256(payload).hexdigest() != expected_sha256:
        raise TrainingSourceAuditError("raw manifest differs from authenticated identity")
    value = _strict_json(payload, "raw manifest")
    if not isinstance(value, Mapping):
        raise TrainingSourceAuditError("raw manifest must be an object")
    return json.loads(canonical_json_bytes(value))


def _authenticated_raw_input(
    corpus_dir: Path,
    source_root: Path,
    expected_corpus_sha256: str,
    expected_manifest_sha256: str,
) -> tuple[dict[str, Any], tuple[dict[str, Any], ...], dict[str, Any]]:
    _sha(expected_corpus_sha256, "expected_corpus_sha256")
    _sha(expected_manifest_sha256, "expected_manifest_sha256")
    try:
        opening = validate_training_corpus_artifacts(
            corpus_dir,
            expected_corpus_sha256=expected_corpus_sha256,
            expected_manifest_sha256=expected_manifest_sha256,
            source_root=source_root,
            require_authenticated=True,
        )
    except TrainingCorpusError as exc:
        raise TrainingSourceAuditError(
            f"authenticated raw corpus verification failed: {exc.issues[0]}"
        ) from exc
    authentication = opening.get("authentication")
    if (
        opening.get("authenticated") is not True
        or not isinstance(authentication, Mapping)
        or authentication.get("external_pin_verified") is not True
        or authentication.get("source_replay_verified") is not True
    ):
        raise TrainingSourceAuditError(
            "raw corpus must verify both external pins and byte-for-byte source replay"
        )
    manifest = _load_raw_manifest(corpus_dir, expected_manifest_sha256)
    records = _read_raw_target_records(corpus_dir, opening["target_file_sha256"])
    try:
        closing = validate_training_corpus_artifacts(
            corpus_dir,
            expected_corpus_sha256=expected_corpus_sha256,
            expected_manifest_sha256=expected_manifest_sha256,
            source_root=source_root,
            require_authenticated=True,
        )
    except TrainingCorpusError as exc:
        raise TrainingSourceAuditError(
            f"closing authenticated raw corpus verification failed: {exc.issues[0]}"
        ) from exc
    if closing != opening:
        raise TrainingSourceAuditError("raw corpus verification changed during audit read")
    if len(records) != opening["target_records"]:
        raise TrainingSourceAuditError("raw target record count changed during audit read")
    return opening, records, manifest


def _evaluation_bindings(value: object | None) -> dict[str, str | None]:
    if value is None:
        return {key: None for key in sorted(_EVALUATION_BINDING_KEYS)}
    binding = _exact_keys(value, _EVALUATION_BINDING_KEYS, "evaluation_bindings")
    normalized: dict[str, str | None] = {}
    for key in sorted(_EVALUATION_BINDING_KEYS):
        item = binding[key]
        normalized[key] = None if item is None else _sha(item, f"evaluation_bindings.{key}")
    return normalized


def _audit_record(prefix: str, core: Mapping[str, Any]) -> dict[str, Any]:
    digest = value_sha256(core)
    return {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "audit_record_id": f"{prefix}-{digest[:24]}",
        "audit_record_sha256": digest,
        **json.loads(canonical_json_bytes(core)),
    }


def _candidate_record(
    source_record: Mapping[str, Any],
    source_ordinal: int,
    normalized_prompt_sha256: str,
    classification: Mapping[str, Any],
) -> dict[str, Any]:
    core = {
        "record_type": "cbds.training-source-static-candidate",
        "source_record_id": source_record["record_id"],
        "source_record_sha256": source_record["record_sha256"],
        "source_ordinal": source_ordinal,
        "normalized_prompt_sha256": normalized_prompt_sha256,
        "prompt": source_record["prompt"],
        "completion": source_record["completion"],
        "classification": classification,
    }
    return _audit_record("tsa-c", core)


def _rejection_record(
    source_record: Mapping[str, Any],
    source_ordinal: int,
    normalized_prompt_sha256: str,
    classification: Mapping[str, Any],
) -> dict[str, Any]:
    core = {
        "record_type": "cbds.training-source-rejection",
        "source_record_id": source_record["record_id"],
        "source_record_sha256": source_record["record_sha256"],
        "source_ordinal": source_ordinal,
        "normalized_prompt_sha256": normalized_prompt_sha256,
        "completion_sha256": _completion_digest(source_record["completion"]),
        "classifier_policy_sha256": classification["classifier_policy_sha256"],
        "reason_codes": classification["reason_codes"],
    }
    return _audit_record("tsa-r", core)


def _jsonl(records: Iterable[Mapping[str, Any]]) -> bytes:
    return b"".join(canonical_json_bytes(record) + b"\n" for record in records)


def _sequence_sha256(record_type: str, digests: list[str]) -> str:
    return value_sha256(
        {
            "contract": "cbds.training-source-audit-record-sequence",
            "version": AUDIT_SCHEMA_VERSION,
            "record_type": record_type,
            "audit_record_sha256s": digests,
        }
    )


def _set_sha256(record_type: str, digests: list[str]) -> str:
    return value_sha256(
        {
            "contract": "cbds.training-source-audit-record-set",
            "version": AUDIT_SCHEMA_VERSION,
            "record_type": record_type,
            "audit_record_sha256s": sorted(digests),
        }
    )


def _file_declaration(path: str, payload: bytes, records: list[dict[str, Any]]) -> dict[str, Any]:
    record_type = records[0]["record_type"] if records else (
        "cbds.training-source-static-candidate"
        if path == CANDIDATE_FILE_NAME
        else "cbds.training-source-rejection"
    )
    digests = [record["audit_record_sha256"] for record in records]
    return {
        "path": path,
        "bytes": len(payload),
        "records": len(records),
        "sha256": sha256(payload).hexdigest(),
        "record_set_sha256": _set_sha256(record_type, digests),
        "record_sequence_sha256": _sequence_sha256(record_type, digests),
    }


def _stable_source_identity(module: Any, module_name: str) -> dict[str, str]:
    path_value = getattr(module, "__file__", None)
    if not isinstance(path_value, str):
        raise TrainingSourceAuditError(f"transformation module {module_name} has no source path")
    payload = _read_regular(Path(path_value), 8 * 1024 * 1024, f"source for {module_name}")
    return {"module": module_name, "sha256": sha256(payload).hexdigest()}


def _transformation_sources() -> list[dict[str, str]]:
    import sys

    current = sys.modules[__name__]
    records = [
        _stable_source_identity(current, "cbds.training_source_audit"),
        _stable_source_identity(manifests_module, "cbds.manifests"),
        _stable_source_identity(training_corpus_module, "cbds.training_corpus"),
    ]
    return sorted(records, key=lambda item: item["module"].encode("utf-8"))


def _histograms(
    source_records: tuple[dict[str, Any], ...],
    classifications: list[dict[str, Any]],
    normalized_prompts: list[str],
) -> dict[str, Any]:
    reason_counts: Counter[str] = Counter()
    utility_occurrences: Counter[str] = Counter()
    utility_records: Counter[str] = Counter()
    utility_candidates: Counter[str] = Counter()
    utility_rejections: Counter[str] = Counter()
    histogram_vocabulary = (
        _POSITIVE_EXECUTABLE_ALLOWLIST | _DYNAMIC_COMMANDS | _SHELL_WRAPPERS
    )
    for classification in classifications:
        reason_counts.update(classification["reason_codes"])
        utilities = [
            utility if utility in histogram_vocabulary else "__not_allowlisted__"
            for utility in classification["observed_utilities"]
        ]
        utility_occurrences.update(utilities)
        for utility in set(utilities):
            utility_records[utility] += 1
            if classification["status"] == "static_candidate":
                utility_candidates[utility] += 1
            else:
                utility_rejections[utility] += 1

    groups: dict[str, list[int]] = defaultdict(list)
    for ordinal, normalized in enumerate(normalized_prompts):
        groups[normalized].append(ordinal)
    group_size_counts: Counter[int] = Counter(len(values) for values in groups.values())
    ambiguous_distinct_counts: Counter[int] = Counter()
    ambiguous_records = 0
    ambiguous_groups = 0
    for ordinals in groups.values():
        completions = {
            source_records[ordinal]["completion"] for ordinal in ordinals
        }
        if len(completions) > 1:
            ambiguous_groups += 1
            ambiguous_records += len(ordinals)
            ambiguous_distinct_counts[len(completions)] += 1
    return {
        "reasons": [
            {"reason_code": reason, "records": reason_counts[reason]}
            for reason in _REASON_ORDER
            if reason_counts[reason]
        ],
        "utilities": [
            {
                "utility": utility,
                "occurrences": utility_occurrences[utility],
                "records": utility_records[utility],
                "static_candidate_records": utility_candidates[utility],
                "rejected_records": utility_rejections[utility],
            }
            for utility in sorted(utility_occurrences, key=lambda value: value.encode("utf-8"))
        ],
        "normalized_prompt_collisions": {
            "normalization": "NFKC_casefold_unicode_whitespace_to_ascii_space_strip",
            "groups": len(groups),
            "ambiguous_groups": ambiguous_groups,
            "ambiguous_records": ambiguous_records,
            "group_size_histogram": [
                {"group_size": size, "groups": group_size_counts[size]}
                for size in sorted(group_size_counts)
            ],
            "distinct_completion_histogram_for_ambiguous_groups": [
                {
                    "distinct_completions": count,
                    "groups": ambiguous_distinct_counts[count],
                }
                for count in sorted(ambiguous_distinct_counts)
            ],
        },
    }


def _raw_target_sequence_sha256(raw_manifest: Mapping[str, Any]) -> str:
    partitions = raw_manifest.get("partitions")
    if not isinstance(partitions, list):
        raise TrainingSourceAuditError("raw manifest partitions are unavailable")
    for declaration in partitions:
        if isinstance(declaration, Mapping) and declaration.get("partition") == "target":
            return _sha(
                declaration.get("record_sequence_sha256"),
                "raw target record_sequence_sha256",
            )
    raise TrainingSourceAuditError("raw target sequence binding is unavailable")


def _construct_artifact(
    audit_id: str,
    corpus_dir: Path,
    source_root: Path,
    expected_corpus_sha256: str,
    expected_manifest_sha256: str,
    evaluation_bindings: object | None,
) -> tuple[dict[str, Any], bytes, bytes, bytes]:
    audit_id = _identifier(audit_id, "audit_id")
    bindings = _evaluation_bindings(evaluation_bindings)
    raw_summary, source_records, raw_manifest = _authenticated_raw_input(
        corpus_dir,
        source_root,
        expected_corpus_sha256,
        expected_manifest_sha256,
    )
    normalized_prompts = [
        normalize_prompt_for_collision(record["prompt"]) for record in source_records
    ]
    prompt_completions: dict[str, set[str]] = defaultdict(set)
    for normalized, record in zip(normalized_prompts, source_records, strict=True):
        prompt_completions[normalized].add(record["completion"])
    ambiguous = {
        normalized for normalized, completions in prompt_completions.items() if len(completions) > 1
    }

    candidates: list[dict[str, Any]] = []
    rejections: list[dict[str, Any]] = []
    classifications: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    for ordinal, (source_record, normalized) in enumerate(
        zip(source_records, normalized_prompts, strict=True)
    ):
        classification = classify_target_command_lexically(
            source_record["completion"],
            ambiguous_normalized_prompt=normalized in ambiguous,
        )
        classifications.append(classification)
        normalized_digest = _prompt_digest(normalized)
        if classification["status"] == "static_candidate":
            record = _candidate_record(
                source_record,
                ordinal,
                normalized_digest,
                classification,
            )
            candidates.append(record)
            decision = "static_candidate"
        else:
            record = _rejection_record(
                source_record,
                ordinal,
                normalized_digest,
                classification,
            )
            rejections.append(record)
            decision = "rejected"
        decisions.append(
            {
                "source_record_id": source_record["record_id"],
                "source_record_sha256": source_record["record_sha256"],
                "source_ordinal": ordinal,
                "decision": decision,
                "audit_record_sha256": record["audit_record_sha256"],
            }
        )

    candidate_payload = _jsonl(candidates)
    rejection_payload = _jsonl(rejections)
    sources = _transformation_sources()
    policy = classifier_policy()
    manifest_core: dict[str, Any] = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "record_type": "cbds.training-source-audit-manifest",
        "audit_id": audit_id,
        "preparer": {
            "name": "cbds.training_source_audit",
            "version": AUDIT_PREPARER_VERSION,
            "runtime": {
                "python_implementation": platform.python_implementation(),
                "python_version": platform.python_version(),
                "unicode_database_version": unicodedata.unidata_version,
            },
            "transformation_sources": sources,
            "transformation_sources_sha256": value_sha256(
                {
                    "contract": "cbds.training-source-audit-transformation-sources",
                    "version": AUDIT_SCHEMA_VERSION,
                    "sources": sources,
                }
            ),
        },
        "classifier_policy": policy,
        "classifier_policy_sha256": value_sha256(policy),
        "raw_source": {
            "corpus_id": raw_summary["corpus_id"],
            "corpus_sha256": raw_summary["corpus_sha256"],
            "manifest_sha256": raw_summary["manifest_sha256"],
            "config_sha256": raw_summary["config_sha256"],
            "target_file_sha256": raw_summary["target_file_sha256"],
            "target_record_sequence_sha256": _raw_target_sequence_sha256(raw_manifest),
            "target_records": raw_summary["target_records"],
            "raw_training_csv_sha256": raw_manifest["target_source"]["file_sha256"],
            "dataset_card_sha256": raw_manifest["target_source"]["dataset_card_sha256"],
            "external_corpus_pin_verified": True,
            "external_manifest_pin_verified": True,
            "source_replay_verified": True,
            "authenticated": True,
        },
        "evaluation_bindings": {
            "slots": bindings,
            "bound_slots": sum(value is not None for value in bindings.values()),
            "overlap_analysis_performed": False,
        },
        "files": [
            _file_declaration(CANDIDATE_FILE_NAME, candidate_payload, candidates),
            _file_declaration(REJECTION_FILE_NAME, rejection_payload, rejections),
        ],
        "counts": {
            "source_records": len(source_records),
            "static_candidates": len(candidates),
            "rejected": len(rejections),
        },
        "histograms": _histograms(source_records, classifications, normalized_prompts),
        "decision_sequence_sha256": value_sha256(
            {
                "contract": "cbds.training-source-audit-decision-sequence",
                "version": AUDIT_SCHEMA_VERSION,
                "decisions": decisions,
            }
        ),
        "quality_scope": _QUALITY_SCOPE,
        "limitations": list(_LIMITATIONS),
        "audit_hash_scope": "canonical_json_excluding_audit_sha256",
    }
    manifest = dict(manifest_core)
    manifest["audit_sha256"] = value_sha256(manifest_core)
    manifest_payload = (
        json.dumps(manifest, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")
    if len(candidate_payload) > MAX_LEDGER_BYTES:
        raise TrainingSourceAuditError("candidate ledger exceeds its publication byte limit")
    if len(rejection_payload) > MAX_LEDGER_BYTES:
        raise TrainingSourceAuditError("rejection ledger exceeds its publication byte limit")
    if len(manifest_payload) > MAX_MANIFEST_BYTES:
        raise TrainingSourceAuditError("audit manifest exceeds its publication byte limit")
    return manifest, candidate_payload, rejection_payload, manifest_payload


def _write_new_at(directory_descriptor: int, name: str, payload: bytes) -> None:
    if not name or "/" in name or name in {".", ".."}:
        raise TrainingSourceAuditError("artifact member name is invalid")
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
    parent_descriptor: int, staging_name: str, destination_name: str
) -> None:
    """Atomically publish a staging directory without replacing any name."""

    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as exc:  # pragma: no cover - Linux experiment requirement
        raise TrainingSourceAuditError("platform lacks renameat2") from exc
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
        os.fsencode(staging_name),
        parent_descriptor,
        os.fsencode(destination_name),
        1,  # RENAME_NOREPLACE
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        raise TrainingSourceAuditError("output directory already exists")
    raise TrainingSourceAuditError(
        f"cannot atomically publish audit directory: {errno.errorcode.get(error_number, 'ERROR')}"
    )


def _remove_staging_directory(
    parent_descriptor: int, staging_descriptor: int, staging_name: str
) -> None:
    """Best-effort cleanup limited to the private staging directory."""

    try:
        for name in os.listdir(staging_descriptor):
            try:
                os.unlink(name, dir_fd=staging_descriptor)
            except FileNotFoundError:
                pass
    finally:
        try:
            os.rmdir(staging_name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass


def _new_staging_directory(parent_descriptor: int, destination_name: str) -> tuple[str, int]:
    prefix = f".{destination_name}.staging-"
    for _ in range(64):
        name = prefix + os.urandom(16).hex()
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_descriptor)
        except FileExistsError:
            continue
        try:
            descriptor = os.open(name, _directory_open_flags(), dir_fd=parent_descriptor)
        except BaseException:
            try:
                os.rmdir(name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
            raise
        return name, descriptor
    raise TrainingSourceAuditError("cannot allocate a private audit staging directory")


def prepare_training_source_audit(
    *,
    audit_id: str,
    corpus_dir: str | os.PathLike[str],
    source_root: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
    expected_corpus_sha256: str,
    expected_manifest_sha256: str,
    evaluation_bindings: object | None = None,
) -> dict[str, Any]:
    """Prepare a lexical audit from a doubly pinned, source-replayed corpus."""

    manifest, candidate_payload, rejection_payload, manifest_payload = _construct_artifact(
        audit_id,
        Path(corpus_dir),
        Path(source_root),
        expected_corpus_sha256,
        expected_manifest_sha256,
        evaluation_bindings,
    )
    destination = Path(output_dir)
    destination_name = destination.name
    if destination_name in {"", ".", ".."} or "/" in destination_name:
        raise TrainingSourceAuditError("output directory name is invalid")
    parent_descriptor = _open_directory_path(destination.parent, create=True)
    staging_name = ""
    staging_descriptor = -1
    published = False
    try:
        staging_name, staging_descriptor = _new_staging_directory(
            parent_descriptor, destination_name
        )
        _write_new_at(staging_descriptor, CANDIDATE_FILE_NAME, candidate_payload)
        _write_new_at(staging_descriptor, REJECTION_FILE_NAME, rejection_payload)
        _write_new_at(staging_descriptor, MANIFEST_FILE_NAME, manifest_payload)
        sidecar = f"{sha256(manifest_payload).hexdigest()}  {MANIFEST_FILE_NAME}\n".encode(
            "ascii"
        )
        _write_new_at(staging_descriptor, MANIFEST_SIDECAR_NAME, sidecar)
        os.fsync(staging_descriptor)
        named_staging = os.stat(
            staging_name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        opened_staging = os.fstat(staging_descriptor)
        if (
            named_staging.st_dev != opened_staging.st_dev
            or named_staging.st_ino != opened_staging.st_ino
            or not stat.S_ISDIR(named_staging.st_mode)
            or set(os.listdir(staging_descriptor))
            != {
                CANDIDATE_FILE_NAME,
                REJECTION_FILE_NAME,
                MANIFEST_FILE_NAME,
                MANIFEST_SIDECAR_NAME,
            }
        ):
            raise TrainingSourceAuditError("audit staging directory changed before publication")
        _rename_directory_noreplace(parent_descriptor, staging_name, destination_name)
        published = True
        named_destination = os.stat(
            destination_name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        if (
            named_destination.st_dev != opened_staging.st_dev
            or named_destination.st_ino != opened_staging.st_ino
            or not stat.S_ISDIR(named_destination.st_mode)
        ):
            raise TrainingSourceAuditError("published audit directory identity differs")
        os.fsync(parent_descriptor)
    finally:
        if staging_descriptor >= 0:
            if not published:
                _remove_staging_directory(
                    parent_descriptor, staging_descriptor, staging_name
                )
            os.close(staging_descriptor)
        os.close(parent_descriptor)
    published_descriptor = _open_directory_path(destination, create=False)
    try:
        published_metadata = os.fstat(published_descriptor)
    finally:
        os.close(published_descriptor)
    if (
        published_metadata.st_dev != opened_staging.st_dev
        or published_metadata.st_ino != opened_staging.st_ino
    ):
        raise TrainingSourceAuditError("output path changed after audit publication")
    return {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "audit_id": manifest["audit_id"],
        "audit_sha256": manifest["audit_sha256"],
        "manifest_sha256": sha256(manifest_payload).hexdigest(),
        "source_records": manifest["counts"]["source_records"],
        "static_candidates": manifest["counts"]["static_candidates"],
        "rejected": manifest["counts"]["rejected"],
        "ast_parsed": False,
        "execution_verified": False,
        "training_eligible": False,
        "target_policy_accepted": False,
        "claim_authorized": False,
    }


def _validate_audit_record(value: object, expected_type: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TrainingSourceAuditError("audit record must be an object")
    candidate_keys = {
        "schema_version",
        "audit_record_id",
        "audit_record_sha256",
        "record_type",
        "source_record_id",
        "source_record_sha256",
        "source_ordinal",
        "normalized_prompt_sha256",
        "prompt",
        "completion",
        "classification",
    }
    rejection_keys = {
        "schema_version",
        "audit_record_id",
        "audit_record_sha256",
        "record_type",
        "source_record_id",
        "source_record_sha256",
        "source_ordinal",
        "normalized_prompt_sha256",
        "completion_sha256",
        "classifier_policy_sha256",
        "reason_codes",
    }
    expected_keys = candidate_keys if expected_type.endswith("static-candidate") else rejection_keys
    if set(value) != expected_keys or value.get("record_type") != expected_type:
        raise TrainingSourceAuditError("audit record schema is invalid")
    if value.get("schema_version") != AUDIT_SCHEMA_VERSION:
        raise TrainingSourceAuditError("audit record schema version is invalid")
    source_ordinal = value.get("source_ordinal")
    if isinstance(source_ordinal, bool) or not isinstance(source_ordinal, int) or source_ordinal < 0:
        raise TrainingSourceAuditError("audit record source_ordinal is invalid")
    _identifier(value.get("source_record_id"), "audit source_record_id")
    _sha(value.get("source_record_sha256"), "audit source_record_sha256")
    _sha(value.get("normalized_prompt_sha256"), "normalized_prompt_sha256")
    declared = _sha(value.get("audit_record_sha256"), "audit_record_sha256")
    identifier = value.get("audit_record_id")
    prefix = "tsa-c" if expected_type.endswith("static-candidate") else "tsa-r"
    core = dict(value)
    core.pop("schema_version")
    core.pop("audit_record_id")
    core.pop("audit_record_sha256")
    computed = value_sha256(core)
    if declared != computed or identifier != f"{prefix}-{computed[:24]}":
        raise TrainingSourceAuditError("audit record content address does not verify")
    if expected_type.endswith("static-candidate"):
        if not isinstance(value.get("prompt"), str) or not isinstance(value.get("completion"), str):
            raise TrainingSourceAuditError("candidate plaintext fields must be strings")
        if value["normalized_prompt_sha256"] != _prompt_digest(
            normalize_prompt_for_collision(value["prompt"])
        ):
            raise TrainingSourceAuditError("candidate normalized-prompt hash differs")
        classification = value.get("classification")
        expected_classification = classify_target_command_lexically(value["completion"])
        if (
            not isinstance(classification, Mapping)
            or dict(classification) != expected_classification
        ):
            raise TrainingSourceAuditError("candidate classification is not fail-closed")
    else:
        _sha(value.get("completion_sha256"), "rejection completion_sha256")
        _sha(value.get("classifier_policy_sha256"), "rejection classifier_policy_sha256")
        reasons = value.get("reason_codes")
        if not isinstance(reasons, list) or not reasons or reasons != _reason_sort(reasons):
            raise TrainingSourceAuditError("rejection reason codes are invalid")
    return json.loads(canonical_json_bytes(value))


def _validate_ledger(
    payload: bytes,
    declaration: Mapping[str, Any],
    expected_path: str,
    expected_type: str,
) -> list[dict[str, Any]]:
    expected_keys = {
        "path",
        "bytes",
        "records",
        "sha256",
        "record_set_sha256",
        "record_sequence_sha256",
    }
    if set(declaration) != expected_keys or declaration.get("path") != expected_path:
        raise TrainingSourceAuditError("audit file declaration is invalid")
    if declaration.get("bytes") != len(payload) or declaration.get("sha256") != sha256(payload).hexdigest():
        raise TrainingSourceAuditError("audit ledger file identity differs")
    if payload and not payload.endswith(b"\n"):
        raise TrainingSourceAuditError("audit ledger lacks final LF")
    lines = payload.splitlines()
    if declaration.get("records") != len(lines):
        raise TrainingSourceAuditError("audit ledger record count differs")
    records: list[dict[str, Any]] = []
    previous = -1
    for line in lines:
        value = _strict_json(line, "audit ledger record")
        record = _validate_audit_record(value, expected_type)
        if canonical_json_bytes(record) != line:
            raise TrainingSourceAuditError("audit ledger record is not canonical JSON")
        if record["source_ordinal"] <= previous:
            raise TrainingSourceAuditError("audit ledger source ordinals are not increasing")
        previous = record["source_ordinal"]
        records.append(record)
    digests = [record["audit_record_sha256"] for record in records]
    if declaration.get("record_set_sha256") != _set_sha256(expected_type, digests):
        raise TrainingSourceAuditError("audit ledger record-set hash differs")
    if declaration.get("record_sequence_sha256") != _sequence_sha256(expected_type, digests):
        raise TrainingSourceAuditError("audit ledger record-sequence hash differs")
    return records


def _validate_training_source_audit_artifacts_from_fd(
    root_descriptor: int,
    *,
    expected_audit_sha256: str | None = None,
    expected_manifest_sha256: str | None = None,
    raw_corpus_dir: str | os.PathLike[str] | None = None,
    raw_source_root: str | os.PathLike[str] | None = None,
    raw_expected_corpus_sha256: str | None = None,
    raw_expected_manifest_sha256: str | None = None,
    require_authenticated: bool = False,
) -> dict[str, Any]:
    """Validate an audit artifact and optionally replay its full provenance.

    A caller-supplied audit hash pair authenticates bytes but does not re-prove
    that candidate plaintext came from the raw source.  ``authenticated=True``
    therefore requires both audit pins *and* all four ``raw_*`` arguments; the
    latter reconstruct the complete artifact from a doubly pinned, source-
    replayed corpus and compare every byte.
    """

    if not isinstance(require_authenticated, bool):
        raise TrainingSourceAuditError("require_authenticated must be boolean")
    root_before = os.fstat(root_descriptor)
    if not stat.S_ISDIR(root_before.st_mode):
        raise TrainingSourceAuditError("audit root must be a real directory")
    expected_names = {
        CANDIDATE_FILE_NAME,
        REJECTION_FILE_NAME,
        MANIFEST_FILE_NAME,
        MANIFEST_SIDECAR_NAME,
    }
    if set(os.listdir(root_descriptor)) != expected_names:
        raise TrainingSourceAuditError("audit root inventory is not exact")
    manifest_payload = _read_regular_at(
        root_descriptor, MANIFEST_FILE_NAME, MAX_MANIFEST_BYTES, "audit manifest"
    )
    manifest_digest = sha256(manifest_payload).hexdigest()
    sidecar = _read_regular_at(
        root_descriptor, MANIFEST_SIDECAR_NAME, 1024, "audit sidecar"
    )
    if sidecar != f"{manifest_digest}  {MANIFEST_FILE_NAME}\n".encode("ascii"):
        raise TrainingSourceAuditError("audit manifest sidecar does not verify")
    if expected_manifest_sha256 is not None and _sha(
        expected_manifest_sha256, "expected_manifest_sha256"
    ) != manifest_digest:
        raise TrainingSourceAuditError("audit manifest differs from its external pin")
    manifest = _strict_json(manifest_payload, "audit manifest")
    if not isinstance(manifest, Mapping):
        raise TrainingSourceAuditError("audit manifest must be an object")
    required = {
        "schema_version",
        "record_type",
        "audit_id",
        "preparer",
        "classifier_policy",
        "classifier_policy_sha256",
        "raw_source",
        "evaluation_bindings",
        "files",
        "counts",
        "histograms",
        "decision_sequence_sha256",
        "quality_scope",
        "limitations",
        "audit_hash_scope",
        "audit_sha256",
    }
    if set(manifest) != required:
        raise TrainingSourceAuditError("audit manifest keys are not exact")
    canonical_pretty = (
        json.dumps(manifest, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")
    if canonical_pretty != manifest_payload:
        raise TrainingSourceAuditError("audit manifest bytes are not canonical pretty JSON")
    if (
        manifest.get("schema_version") != AUDIT_SCHEMA_VERSION
        or manifest.get("record_type") != "cbds.training-source-audit-manifest"
    ):
        raise TrainingSourceAuditError("audit manifest identity is invalid")
    _identifier(manifest.get("audit_id"), "manifest.audit_id")
    if manifest.get("quality_scope") != _QUALITY_SCOPE or manifest.get("limitations") != list(_LIMITATIONS):
        raise TrainingSourceAuditError("audit claim boundary is invalid")
    preparer = _exact_keys(
        manifest.get("preparer"),
        frozenset(
            {
                "name",
                "version",
                "runtime",
                "transformation_sources",
                "transformation_sources_sha256",
            }
        ),
        "manifest.preparer",
    )
    if (
        preparer["name"] != "cbds.training_source_audit"
        or preparer["version"] != AUDIT_PREPARER_VERSION
        or not isinstance(preparer["transformation_sources"], list)
    ):
        raise TrainingSourceAuditError("audit preparer identity is invalid")
    runtime = _exact_keys(
        preparer["runtime"],
        frozenset(
            {"python_implementation", "python_version", "unicode_database_version"}
        ),
        "manifest.preparer.runtime",
    )
    if any(not isinstance(runtime[key], str) or not runtime[key] for key in runtime):
        raise TrainingSourceAuditError("audit runtime identity is invalid")
    source_modules = [
        "cbds.manifests",
        "cbds.training_corpus",
        "cbds.training_source_audit",
    ]
    transformation_sources = preparer["transformation_sources"]
    if len(transformation_sources) != len(source_modules):
        raise TrainingSourceAuditError("audit transformation source list is invalid")
    for expected_module, source_record in zip(
        source_modules, transformation_sources, strict=True
    ):
        source_record = _exact_keys(
            source_record, frozenset({"module", "sha256"}), "transformation source"
        )
        if source_record["module"] != expected_module:
            raise TrainingSourceAuditError("audit transformation sources are not in frozen order")
        _sha(source_record["sha256"], "transformation source SHA-256")
    expected_sources_hash = value_sha256(
        {
            "contract": "cbds.training-source-audit-transformation-sources",
            "version": AUDIT_SCHEMA_VERSION,
            "sources": transformation_sources,
        }
    )
    if preparer["transformation_sources_sha256"] != expected_sources_hash:
        raise TrainingSourceAuditError("audit transformation source hash differs")
    policy = manifest.get("classifier_policy")
    if policy != classifier_policy() or manifest.get("classifier_policy_sha256") != _classifier_policy_sha256():
        raise TrainingSourceAuditError("audit classifier policy identity is invalid")
    raw = _exact_keys(
        manifest.get("raw_source"),
        frozenset(
            {
                "corpus_id",
                "corpus_sha256",
                "manifest_sha256",
                "config_sha256",
                "target_file_sha256",
                "target_record_sequence_sha256",
                "target_records",
                "raw_training_csv_sha256",
                "dataset_card_sha256",
                "external_corpus_pin_verified",
                "external_manifest_pin_verified",
                "source_replay_verified",
                "authenticated",
            }
        ),
        "manifest.raw_source",
    )
    _identifier(raw["corpus_id"], "raw_source.corpus_id")
    for key in (
        "corpus_sha256",
        "manifest_sha256",
        "config_sha256",
        "target_file_sha256",
        "target_record_sequence_sha256",
        "raw_training_csv_sha256",
        "dataset_card_sha256",
    ):
        _sha(raw[key], f"raw_source.{key}")
    if (
        isinstance(raw["target_records"], bool)
        or not isinstance(raw["target_records"], int)
        or raw["target_records"] <= 0
        or raw["target_records"] > MAX_RECORDS
    ):
        raise TrainingSourceAuditError("raw source target_records is invalid")
    if any(
        raw.get(key) is not True
        for key in (
            "external_corpus_pin_verified",
            "external_manifest_pin_verified",
            "source_replay_verified",
            "authenticated",
        )
    ):
        raise TrainingSourceAuditError("audit raw-source authentication boundary is invalid")
    evaluation = _exact_keys(
        manifest.get("evaluation_bindings"),
        frozenset({"slots", "bound_slots", "overlap_analysis_performed"}),
        "manifest.evaluation_bindings",
    )
    slots = _exact_keys(
        evaluation["slots"], _EVALUATION_BINDING_KEYS, "evaluation binding slots"
    )
    normalized_slots = _evaluation_bindings(slots)
    bound_slots = sum(value is not None for value in normalized_slots.values())
    if (
        evaluation["bound_slots"] != bound_slots
        or evaluation["overlap_analysis_performed"] is not False
    ):
        raise TrainingSourceAuditError("audit evaluation binding boundary is invalid")
    files = manifest.get("files")
    if not isinstance(files, list) or len(files) != 2:
        raise TrainingSourceAuditError("audit manifest must declare two ledgers")
    if [item.get("path") for item in files if isinstance(item, Mapping)] != [
        CANDIDATE_FILE_NAME,
        REJECTION_FILE_NAME,
    ]:
        raise TrainingSourceAuditError("audit ledgers are not in frozen order")
    candidate_payload = _read_regular_at(
        root_descriptor, CANDIDATE_FILE_NAME, MAX_LEDGER_BYTES, "candidate ledger"
    )
    rejection_payload = _read_regular_at(
        root_descriptor, REJECTION_FILE_NAME, MAX_LEDGER_BYTES, "rejection ledger"
    )
    candidates = _validate_ledger(
        candidate_payload,
        files[0],
        CANDIDATE_FILE_NAME,
        "cbds.training-source-static-candidate",
    )
    rejections = _validate_ledger(
        rejection_payload,
        files[1],
        REJECTION_FILE_NAME,
        "cbds.training-source-rejection",
    )
    all_records = sorted(candidates + rejections, key=lambda item: item["source_ordinal"])
    if [item["source_ordinal"] for item in all_records] != list(range(len(all_records))):
        raise TrainingSourceAuditError("audit decisions do not cover one exact source sequence")
    if len({item["source_record_id"] for item in all_records}) != len(all_records):
        raise TrainingSourceAuditError("audit decisions contain duplicate source identities")
    decisions = [
        {
            "source_record_id": item["source_record_id"],
            "source_record_sha256": item["source_record_sha256"],
            "source_ordinal": item["source_ordinal"],
            "decision": (
                "static_candidate"
                if item["record_type"].endswith("static-candidate")
                else "rejected"
            ),
            "audit_record_sha256": item["audit_record_sha256"],
        }
        for item in all_records
    ]
    expected_decision_hash = value_sha256(
        {
            "contract": "cbds.training-source-audit-decision-sequence",
            "version": AUDIT_SCHEMA_VERSION,
            "decisions": decisions,
        }
    )
    if manifest.get("decision_sequence_sha256") != expected_decision_hash:
        raise TrainingSourceAuditError("audit decision-sequence hash differs")
    counts = manifest.get("counts")
    expected_counts = {
        "source_records": len(all_records),
        "static_candidates": len(candidates),
        "rejected": len(rejections),
    }
    if counts != expected_counts or raw.get("target_records") != len(all_records):
        raise TrainingSourceAuditError("audit counts do not reproduce")
    histograms = _exact_keys(
        manifest.get("histograms"),
        frozenset({"reasons", "utilities", "normalized_prompt_collisions"}),
        "manifest.histograms",
    )
    reason_counts: Counter[str] = Counter()
    for rejection in rejections:
        reason_counts.update(rejection["reason_codes"])
        if rejection["classifier_policy_sha256"] != _classifier_policy_sha256():
            raise TrainingSourceAuditError("rejection classifier policy hash differs")
    expected_reason_histogram = [
        {"reason_code": reason, "records": reason_counts[reason]}
        for reason in _REASON_ORDER
        if reason_counts[reason]
    ]
    if histograms["reasons"] != expected_reason_histogram:
        raise TrainingSourceAuditError("audit reason histogram does not reproduce")
    utility_items = histograms["utilities"]
    if not isinstance(utility_items, list):
        raise TrainingSourceAuditError("audit utility histogram must be a list")
    permitted_histogram_utilities = (
        _POSITIVE_EXECUTABLE_ALLOWLIST
        | _DYNAMIC_COMMANDS
        | _SHELL_WRAPPERS
        | {"__not_allowlisted__"}
    )
    declared_candidate_utility_records: dict[str, int] = {}
    utility_labels: list[str] = []
    for item in utility_items:
        item = _exact_keys(
            item,
            frozenset(
                {
                    "utility",
                    "occurrences",
                    "records",
                    "static_candidate_records",
                    "rejected_records",
                }
            ),
            "utility histogram entry",
        )
        utility = item["utility"]
        if not isinstance(utility, str) or utility not in permitted_histogram_utilities:
            raise TrainingSourceAuditError(
                "audit utility histogram contains an unapproved label"
            )
        utility_labels.append(utility)
        for key in (
            "occurrences",
            "records",
            "static_candidate_records",
            "rejected_records",
        ):
            count = item[key]
            maximum = MAX_TARGET_BYTES if key == "occurrences" else len(all_records)
            if (
                isinstance(count, bool)
                or not isinstance(count, int)
                or count < 0
                or count > maximum
            ):
                raise TrainingSourceAuditError(
                    "audit utility histogram count is invalid"
                )
        if (
            item["records"] <= 0
            or item["occurrences"] < item["records"]
            or item["records"]
            != item["static_candidate_records"] + item["rejected_records"]
            or item["static_candidate_records"] > len(candidates)
            or item["rejected_records"] > len(rejections)
        ):
            raise TrainingSourceAuditError(
                "audit utility histogram arithmetic is invalid"
            )
        if item["static_candidate_records"]:
            declared_candidate_utility_records[utility] = item[
                "static_candidate_records"
            ]
    if utility_labels != sorted(utility_labels, key=lambda value: value.encode("utf-8")) or len(
        set(utility_labels)
    ) != len(utility_labels):
        raise TrainingSourceAuditError("audit utility histogram order is invalid")
    reproduced_candidate_utility_records: Counter[str] = Counter()
    for candidate in candidates:
        reproduced_candidate_utility_records.update(
            set(candidate["classification"]["observed_utilities"])
        )
    if declared_candidate_utility_records != dict(reproduced_candidate_utility_records):
        raise TrainingSourceAuditError(
            "audit candidate utility histogram does not reproduce"
        )

    collision = _exact_keys(
        histograms["normalized_prompt_collisions"],
        frozenset(
            {
                "normalization",
                "groups",
                "ambiguous_groups",
                "ambiguous_records",
                "group_size_histogram",
                "distinct_completion_histogram_for_ambiguous_groups",
            }
        ),
        "normalized-prompt collision histogram",
    )
    if (
        collision["normalization"]
        != "NFKC_casefold_unicode_whitespace_to_ascii_space_strip"
    ):
        raise TrainingSourceAuditError("audit prompt normalization identity differs")
    for key in ("groups", "ambiguous_groups", "ambiguous_records"):
        count = collision[key]
        if (
            isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
            or count > len(all_records)
        ):
            raise TrainingSourceAuditError("audit prompt collision count is invalid")
    if (
        collision["groups"] <= 0
        or collision["ambiguous_groups"] > collision["groups"]
        or collision["ambiguous_records"]
        < 2 * collision["ambiguous_groups"]
        or collision["ambiguous_records"]
        != reason_counts["ambiguous_normalized_prompt"]
    ):
        raise TrainingSourceAuditError("audit prompt collision arithmetic is invalid")

    group_histogram = collision["group_size_histogram"]
    if not isinstance(group_histogram, list) or not group_histogram:
        raise TrainingSourceAuditError("audit group-size histogram is invalid")
    group_sizes: list[int] = []
    reproduced_groups = 0
    reproduced_records = 0
    for item in group_histogram:
        item = _exact_keys(
            item, frozenset({"group_size", "groups"}), "group-size histogram entry"
        )
        size = item["group_size"]
        groups = item["groups"]
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
            or size > len(all_records)
            or isinstance(groups, bool)
            or not isinstance(groups, int)
            or groups <= 0
            or groups > len(all_records)
        ):
            raise TrainingSourceAuditError("audit group-size histogram count is invalid")
        group_sizes.append(size)
        reproduced_groups += groups
        reproduced_records += size * groups
    if (
        group_sizes != sorted(set(group_sizes))
        or reproduced_groups != collision["groups"]
        or reproduced_records != len(all_records)
    ):
        raise TrainingSourceAuditError("audit group-size histogram does not reproduce")

    distinct_histogram = collision[
        "distinct_completion_histogram_for_ambiguous_groups"
    ]
    if not isinstance(distinct_histogram, list):
        raise TrainingSourceAuditError("audit ambiguous-completion histogram is invalid")
    distinct_counts: list[int] = []
    reproduced_ambiguous_groups = 0
    for item in distinct_histogram:
        item = _exact_keys(
            item,
            frozenset({"distinct_completions", "groups"}),
            "ambiguous-completion histogram entry",
        )
        distinct = item["distinct_completions"]
        groups = item["groups"]
        if (
            isinstance(distinct, bool)
            or not isinstance(distinct, int)
            or distinct < 2
            or distinct > len(all_records)
            or isinstance(groups, bool)
            or not isinstance(groups, int)
            or groups <= 0
            or groups > len(all_records)
        ):
            raise TrainingSourceAuditError(
                "audit ambiguous-completion histogram count is invalid"
            )
        distinct_counts.append(distinct)
        reproduced_ambiguous_groups += groups
    if (
        distinct_counts != sorted(set(distinct_counts))
        or reproduced_ambiguous_groups != collision["ambiguous_groups"]
    ):
        raise TrainingSourceAuditError(
            "audit ambiguous-completion histogram does not reproduce"
        )
    declared = _sha(manifest.get("audit_sha256"), "manifest.audit_sha256")
    if manifest.get("audit_hash_scope") != "canonical_json_excluding_audit_sha256":
        raise TrainingSourceAuditError("audit hash scope is invalid")
    unsigned = dict(manifest)
    unsigned.pop("audit_sha256")
    if value_sha256(unsigned) != declared:
        raise TrainingSourceAuditError("audit content address does not reproduce")
    if expected_audit_sha256 is not None and _sha(
        expected_audit_sha256, "expected_audit_sha256"
    ) != declared:
        raise TrainingSourceAuditError("audit identity differs from its external pin")
    artifact_pins_verified = (
        expected_audit_sha256 is not None and expected_manifest_sha256 is not None
    )
    raw_arguments = (
        raw_corpus_dir,
        raw_source_root,
        raw_expected_corpus_sha256,
        raw_expected_manifest_sha256,
    )
    if any(value is not None for value in raw_arguments) and not all(
        value is not None for value in raw_arguments
    ):
        raise TrainingSourceAuditError(
            "raw provenance replay requires corpus directory, source root, and both raw pins"
        )
    raw_source_reverified = False
    if all(value is not None for value in raw_arguments):
        (
            reconstructed_manifest,
            reconstructed_candidates,
            reconstructed_rejections,
            reconstructed_manifest_payload,
        ) = _construct_artifact(
            manifest["audit_id"],
            Path(os.fspath(raw_corpus_dir)),
            Path(os.fspath(raw_source_root)),
            str(raw_expected_corpus_sha256),
            str(raw_expected_manifest_sha256),
            evaluation["slots"],
        )
        if (
            candidate_payload != reconstructed_candidates
            or rejection_payload != reconstructed_rejections
            or manifest_payload != reconstructed_manifest_payload
            or dict(manifest) != reconstructed_manifest
        ):
            raise TrainingSourceAuditError(
                "audit artifact does not reproduce byte-for-byte from authenticated raw source"
            )
        raw_source_reverified = True
    authenticated = artifact_pins_verified and raw_source_reverified
    if require_authenticated and not authenticated:
        raise TrainingSourceAuditError(
            "authenticated audit verification requires both audit pins and raw provenance replay"
        )
    if set(os.listdir(root_descriptor)) != expected_names:
        raise TrainingSourceAuditError("audit root inventory changed during validation")
    root_after = os.fstat(root_descriptor)
    if _fingerprint(root_before) != _fingerprint(root_after):
        raise TrainingSourceAuditError("audit root changed during validation")
    return {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "valid": True,
        "authenticated": authenticated,
        "artifact_pins_verified": artifact_pins_verified,
        "raw_source_reverified": raw_source_reverified,
        "audit_id": manifest["audit_id"],
        "audit_sha256": declared,
        "manifest_sha256": manifest_digest,
        **expected_counts,
        "ast_parsed": False,
        "execution_verified": False,
        "training_eligible": False,
        "target_policy_accepted": False,
        "claim_authorized": False,
    }


def validate_training_source_audit_artifacts(
    source: str | os.PathLike[str],
    *,
    expected_audit_sha256: str | None = None,
    expected_manifest_sha256: str | None = None,
    raw_corpus_dir: str | os.PathLike[str] | None = None,
    raw_source_root: str | os.PathLike[str] | None = None,
    raw_expected_corpus_sha256: str | None = None,
    raw_expected_manifest_sha256: str | None = None,
    require_authenticated: bool = False,
) -> dict[str, Any]:
    """Validate through one pinned directory descriptor, with optional replay."""

    root_path = Path(source)
    root_descriptor = _open_directory_path(root_path, create=False)
    try:
        opened = os.fstat(root_descriptor)
        result = _validate_training_source_audit_artifacts_from_fd(
            root_descriptor,
            expected_audit_sha256=expected_audit_sha256,
            expected_manifest_sha256=expected_manifest_sha256,
            raw_corpus_dir=raw_corpus_dir,
            raw_source_root=raw_source_root,
            raw_expected_corpus_sha256=raw_expected_corpus_sha256,
            raw_expected_manifest_sha256=raw_expected_manifest_sha256,
            require_authenticated=require_authenticated,
        )
        reopened_descriptor = _open_directory_path(root_path, create=False)
        try:
            reopened = os.fstat(reopened_descriptor)
        finally:
            os.close(reopened_descriptor)
        if (
            opened.st_dev != reopened.st_dev
            or opened.st_ino != reopened.st_ino
            or not stat.S_ISDIR(reopened.st_mode)
        ):
            raise TrainingSourceAuditError("audit root path changed during validation")
        return result
    finally:
        os.close(root_descriptor)


__all__ = [
    "AUDIT_PREPARER_VERSION",
    "AUDIT_SCHEMA_VERSION",
    "CLASSIFIER_VERSION",
    "TrainingSourceAuditError",
    "classifier_policy",
    "classify_target_command_lexically",
    "normalize_prompt_for_collision",
    "prepare_training_source_audit",
    "validate_training_source_audit_artifacts",
]
