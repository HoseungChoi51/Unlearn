"""Frozen extraction and syntax checks for generated terminal programs.

The parser deliberately accepts a very small response grammar: either raw
program text or one Markdown code fence containing the entire response.  It
does not guess a language from program contents.  Callers should pass the
accepted code to the sandbox on standard input rather than writing an
executable host file.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum
import math
import os
import re
import subprocess


DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024
DEFAULT_SYNTAX_TIMEOUT_SECONDS = 5.0


class ProgramLanguage(str, Enum):
    """Languages admitted by the frozen response grammar."""

    BASH = "bash"
    PYTHON = "python"


class ResponseStatus(str, Enum):
    """Machine-readable outcomes shared by parsing and syntax checking."""

    OK = "ok"
    EXTRACTION_FAILURE = "extraction_failure"
    TRUNCATION = "truncation"
    SYNTAX_FAILURE = "syntax_failure"
    CHECK_FAILURE = "check_failure"


@dataclass(frozen=True, slots=True)
class ParsedResponse:
    """Result of extracting a single program from a model response."""

    status: ResponseStatus
    language: ProgramLanguage
    code: str | None
    detail: str | None
    response_bytes: int
    code_bytes: int
    fenced: bool

    @property
    def ok(self) -> bool:
        return self.status is ResponseStatus.OK


@dataclass(frozen=True, slots=True)
class SyntaxResult:
    """Result of checking an already parsed response without executing it."""

    status: ResponseStatus
    language: ProgramLanguage
    detail: str | None
    return_code: int | None

    @property
    def ok(self) -> bool:
        return self.status is ResponseStatus.OK


_OPENING_FENCE = re.compile(r"^[ \t]{0,3}```[ \t]*([A-Za-z0-9_+.-]*)[ \t]*$")
_CLOSING_FENCE = re.compile(r"^[ \t]{0,3}```[ \t]*$")
# Detect any fence-looking line, including one that Markdown itself would not
# accept due to indentation.  Such a line must fail extraction rather than be
# silently treated as raw program text.
_FENCE_PREFIX = re.compile(r"^[ \t]*```")
_BASH_LABELS = frozenset({"", "bash", "sh", "shell"})
_PYTHON_LABELS = frozenset({"python", "python3", "py"})


def _failure(
    status: ResponseStatus,
    detail: str,
    response_bytes: int,
    *,
    language: ProgramLanguage = ProgramLanguage.BASH,
    fenced: bool = False,
) -> ParsedResponse:
    return ParsedResponse(
        status=status,
        language=language,
        code=None,
        detail=detail,
        response_bytes=response_bytes,
        code_bytes=0,
        fenced=fenced,
    )


def _language_from_label(label: str) -> ProgramLanguage | None:
    normalized = label.casefold()
    if normalized in _BASH_LABELS:
        return ProgramLanguage.BASH
    if normalized in _PYTHON_LABELS:
        return ProgramLanguage.PYTHON
    return None


def parse_response(
    text: str,
    max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    *,
    was_truncated: bool = False,
) -> ParsedResponse:
    """Extract one Bash or Python program using the frozen response grammar.

    ``text`` may be raw code or exactly one triple-backtick fence occupying the
    whole response (apart from surrounding whitespace).  Unlabelled fences and
    raw responses are Bash.  Fence labels ``bash``, ``sh``, ``shell``,
    ``python``, ``python3``, and ``py`` are accepted case-insensitively.

    The byte ceiling is applied to the original UTF-8 representation before
    newline normalization.  Oversize and externally reported truncated
    completions return ``TRUNCATION`` and never expose partial code.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a str")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    if not isinstance(was_truncated, bool):
        raise TypeError("was_truncated must be a bool")

    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        return _failure(
            ResponseStatus.EXTRACTION_FAILURE,
            f"response is not valid UTF-8 text: {exc.reason}",
            0,
        )
    response_bytes = len(encoded)
    if was_truncated:
        return _failure(
            ResponseStatus.TRUNCATION,
            "generation reported a truncated completion",
            response_bytes,
        )
    if response_bytes > max_bytes:
        return _failure(
            ResponseStatus.TRUNCATION,
            f"response is {response_bytes} bytes; limit is {max_bytes}",
            response_bytes,
        )
    if "\x00" in text:
        return _failure(
            ResponseStatus.EXTRACTION_FAILURE,
            "response contains a NUL character",
            response_bytes,
        )

    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if not normalized.strip():
        return _failure(
            ResponseStatus.EXTRACTION_FAILURE,
            "response contains no program text",
            response_bytes,
        )

    lines = normalized.split("\n")
    marker_indices = [
        index for index, line in enumerate(lines) if _FENCE_PREFIX.match(line)
    ]
    if not marker_indices:
        return ParsedResponse(
            status=ResponseStatus.OK,
            language=ProgramLanguage.BASH,
            code=normalized,
            detail=None,
            response_bytes=response_bytes,
            code_bytes=len(normalized.encode("utf-8")),
            fenced=False,
        )

    if len(marker_indices) != 2:
        detail = (
            "Markdown code fence is not closed"
            if len(marker_indices) == 1
            else "response contains more than one Markdown code fence"
        )
        return _failure(
            ResponseStatus.EXTRACTION_FAILURE,
            detail,
            response_bytes,
            fenced=True,
        )

    first_nonblank = next(i for i, line in enumerate(lines) if line.strip())
    last_nonblank = len(lines) - 1 - next(
        i for i, line in enumerate(reversed(lines)) if line.strip()
    )
    opening_index, closing_index = marker_indices
    if opening_index != first_nonblank or closing_index != last_nonblank:
        return _failure(
            ResponseStatus.EXTRACTION_FAILURE,
            "prose or other content appears outside the Markdown code fence",
            response_bytes,
            fenced=True,
        )

    opening = _OPENING_FENCE.fullmatch(lines[opening_index])
    if opening is None or _CLOSING_FENCE.fullmatch(lines[closing_index]) is None:
        return _failure(
            ResponseStatus.EXTRACTION_FAILURE,
            "malformed Markdown code fence",
            response_bytes,
            fenced=True,
        )

    language = _language_from_label(opening.group(1))
    if language is None:
        return _failure(
            ResponseStatus.EXTRACTION_FAILURE,
            f"unsupported code-fence language: {opening.group(1)!r}",
            response_bytes,
            fenced=True,
        )

    code = "\n".join(lines[opening_index + 1 : closing_index])
    if not code.strip():
        return _failure(
            ResponseStatus.EXTRACTION_FAILURE,
            "Markdown code fence contains no program text",
            response_bytes,
            language=language,
            fenced=True,
        )

    return ParsedResponse(
        status=ResponseStatus.OK,
        language=language,
        code=code,
        detail=None,
        response_bytes=response_bytes,
        code_bytes=len(code.encode("utf-8")),
        fenced=True,
    )


def check_syntax(
    parsed: ParsedResponse,
    *,
    bash_executable: str = "bash",
    timeout_seconds: float = DEFAULT_SYNTAX_TIMEOUT_SECONDS,
) -> SyntaxResult:
    """Check syntax without executing the extracted program.

    Python uses :func:`ast.parse`; Bash is passed on standard input to
    ``bash --noprofile --norc -n`` with a fixed locale.  ``subprocess`` is
    invoked with an argv sequence and never through a shell.
    """

    if not isinstance(parsed, ParsedResponse):
        raise TypeError("parsed must be a ParsedResponse")
    if not isinstance(bash_executable, str) or not bash_executable:
        raise ValueError("bash_executable must be a non-empty string")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise ValueError("timeout_seconds must be a positive number")
    if not math.isfinite(float(timeout_seconds)) or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be a positive number")

    if not parsed.ok or parsed.code is None:
        return SyntaxResult(
            status=parsed.status,
            language=parsed.language,
            detail=parsed.detail,
            return_code=None,
        )

    if parsed.language is ProgramLanguage.PYTHON:
        try:
            ast.parse(parsed.code, filename="<response>", mode="exec")
        except (MemoryError, RecursionError):
            return SyntaxResult(
                status=ResponseStatus.CHECK_FAILURE,
                language=parsed.language,
                detail="Python syntax checker exhausted parser limits",
                return_code=None,
            )
        except (SyntaxError, ValueError, TypeError) as exc:
            detail = _format_python_syntax_error(exc)
            return SyntaxResult(
                status=ResponseStatus.SYNTAX_FAILURE,
                language=parsed.language,
                detail=detail,
                return_code=None,
            )
        return SyntaxResult(
            status=ResponseStatus.OK,
            language=parsed.language,
            detail=None,
            return_code=0,
        )

    env = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
    }
    try:
        completed = subprocess.run(
            [bash_executable, "--noprofile", "--norc", "-n"],
            input=parsed.code,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=float(timeout_seconds),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return SyntaxResult(
            status=ResponseStatus.CHECK_FAILURE,
            language=parsed.language,
            detail=f"Bash syntax check exceeded {timeout_seconds:g} seconds",
            return_code=None,
        )
    except OSError as exc:
        return SyntaxResult(
            status=ResponseStatus.CHECK_FAILURE,
            language=parsed.language,
            detail=f"Bash syntax checker could not start: {exc}",
            return_code=None,
        )

    if completed.returncode != 0:
        diagnostic = (completed.stderr or "Bash reported invalid syntax").strip()
        return SyntaxResult(
            status=ResponseStatus.SYNTAX_FAILURE,
            language=parsed.language,
            detail=diagnostic,
            return_code=completed.returncode,
        )
    return SyntaxResult(
        status=ResponseStatus.OK,
        language=parsed.language,
        detail=None,
        return_code=0,
    )


def _format_python_syntax_error(exc: BaseException) -> str:
    if isinstance(exc, SyntaxError):
        location = ""
        if exc.lineno is not None:
            location = f" at line {exc.lineno}"
            if exc.offset is not None:
                location += f", column {exc.offset}"
        return f"{exc.msg}{location}"
    return str(exc)


__all__ = [
    "DEFAULT_MAX_RESPONSE_BYTES",
    "DEFAULT_SYNTAX_TIMEOUT_SECONDS",
    "ParsedResponse",
    "ProgramLanguage",
    "ResponseStatus",
    "SyntaxResult",
    "check_syntax",
    "parse_response",
]
