from __future__ import annotations

from dataclasses import FrozenInstanceError
import shutil
import unittest

from cbds.response import (
    ParsedResponse,
    ProgramLanguage,
    ResponseStatus,
    check_syntax,
    parse_response,
)


class ParseResponseTests(unittest.TestCase):
    def test_raw_code_defaults_to_bash_and_normalizes_newlines(self) -> None:
        result = parse_response("printf '%s\\r\\n' ok\r\nprintf done\r")

        self.assertTrue(result.ok)
        self.assertEqual(result.status, ResponseStatus.OK)
        self.assertEqual(result.language, ProgramLanguage.BASH)
        self.assertEqual(result.code, "printf '%s\\r\\n' ok\nprintf done\n")
        self.assertFalse(result.fenced)
        self.assertEqual(result.code_bytes, len(result.code.encode("utf-8")))

    def test_single_fence_selects_language_and_excludes_markers(self) -> None:
        result = parse_response(" \n```python3\r\nprint('안녕')\r\n```\n\t")

        self.assertTrue(result.ok)
        self.assertEqual(result.language, ProgramLanguage.PYTHON)
        self.assertEqual(result.code, "print('안녕')")
        self.assertTrue(result.fenced)

    def test_unlabelled_and_shell_fences_are_bash(self) -> None:
        for label in ("", "bash", "BASH", "sh", "shell"):
            with self.subTest(label=label):
                result = parse_response(f"```{label}\necho ok\n```")
                self.assertEqual(result.language, ProgramLanguage.BASH)
                self.assertTrue(result.ok)

    def test_python_labels_are_explicit_only(self) -> None:
        for label in ("python", "PYTHON", "python3", "py"):
            with self.subTest(label=label):
                result = parse_response(f"```{label}\npass\n```")
                self.assertEqual(result.language, ProgramLanguage.PYTHON)
                self.assertTrue(result.ok)

        raw = parse_response("print('valid Python, but raw')")
        self.assertEqual(raw.language, ProgramLanguage.BASH)

    def test_rejects_prose_around_fence(self) -> None:
        for text in (
            "Here is the program:\n```bash\necho ok\n```",
            "```bash\necho ok\n```\nThis should work.",
        ):
            with self.subTest(text=text):
                result = parse_response(text)
                self.assertEqual(result.status, ResponseStatus.EXTRACTION_FAILURE)
                self.assertIsNone(result.code)

    def test_rejects_multiple_unclosed_and_malformed_fences(self) -> None:
        cases = (
            "```bash\necho one\n```\n```bash\necho two\n```",
            "```bash\necho one",
            "````bash\necho one\n````",
            "```bash extra\necho one\n```",
        )
        for text in cases:
            with self.subTest(text=text):
                result = parse_response(text)
                self.assertEqual(result.status, ResponseStatus.EXTRACTION_FAILURE)
                self.assertIsNone(result.code)

    def test_rejects_unsupported_language_and_empty_input(self) -> None:
        unsupported = parse_response("```javascript\nconsole.log(1)\n```")
        empty_fence = parse_response("```python\n\n```")
        empty_raw = parse_response(" \r\n\t")

        for result in (unsupported, empty_fence, empty_raw):
            self.assertEqual(result.status, ResponseStatus.EXTRACTION_FAILURE)
            self.assertIsNone(result.code)

    def test_byte_limit_uses_original_utf8_and_fails_closed(self) -> None:
        text = "echo 한"
        exact = len(text.encode("utf-8"))
        accepted = parse_response(text, max_bytes=exact)
        truncated = parse_response(text, max_bytes=exact - 1)

        self.assertTrue(accepted.ok)
        self.assertEqual(truncated.status, ResponseStatus.TRUNCATION)
        self.assertIsNone(truncated.code)
        self.assertEqual(truncated.response_bytes, exact)

    def test_external_truncation_signal_fails_closed(self) -> None:
        result = parse_response("echo seemingly-complete", was_truncated=True)

        self.assertEqual(result.status, ResponseStatus.TRUNCATION)
        self.assertIsNone(result.code)

    def test_rejects_nul_and_non_utf8_surrogates(self) -> None:
        nul = parse_response("echo before\x00echo after")
        surrogate = parse_response("echo \ud800")

        self.assertEqual(nul.status, ResponseStatus.EXTRACTION_FAILURE)
        self.assertEqual(surrogate.status, ResponseStatus.EXTRACTION_FAILURE)
        self.assertIsNone(nul.code)
        self.assertIsNone(surrogate.code)

    def test_validates_arguments(self) -> None:
        with self.assertRaises(TypeError):
            parse_response(b"echo no")  # type: ignore[arg-type]
        for value in (0, -1, True, 1.5):
            with self.subTest(max_bytes=value):
                with self.assertRaises(ValueError):
                    parse_response("echo ok", max_bytes=value)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            parse_response("echo ok", was_truncated=1)  # type: ignore[arg-type]

    def test_result_is_immutable(self) -> None:
        result = parse_response("echo ok")
        with self.assertRaises(FrozenInstanceError):
            result.code = "echo changed"  # type: ignore[misc]


class SyntaxCheckTests(unittest.TestCase):
    def test_python_valid_and_invalid_syntax(self) -> None:
        valid = check_syntax(parse_response("```python\nprint('ok')\n```"))
        invalid = check_syntax(parse_response("```python\nif True print('no')\n```"))

        self.assertTrue(valid.ok)
        self.assertEqual(valid.return_code, 0)
        self.assertEqual(invalid.status, ResponseStatus.SYNTAX_FAILURE)
        self.assertIn("line 1", invalid.detail or "")

    def test_python_parser_resource_exhaustion_fails_closed(self) -> None:
        parsed = parse_response("```python\n" + "-" * 50_000 + "1\n```")
        result = check_syntax(parsed)
        self.assertEqual(result.status, ResponseStatus.CHECK_FAILURE)
        self.assertIn("parser limits", result.detail or "")

    @unittest.skipUnless(shutil.which("bash"), "bash is required for Bash syntax tests")
    def test_bash_valid_and_invalid_syntax(self) -> None:
        valid = check_syntax(parse_response("if true; then echo ok; fi"))
        invalid = check_syntax(parse_response("if true; then echo no"))

        self.assertTrue(valid.ok)
        self.assertEqual(valid.return_code, 0)
        self.assertEqual(invalid.status, ResponseStatus.SYNTAX_FAILURE)
        self.assertNotEqual(invalid.return_code, 0)
        self.assertTrue(invalid.detail)

    def test_parse_failure_is_propagated_without_check(self) -> None:
        parsed = parse_response("```bash\necho partial", was_truncated=True)
        checked = check_syntax(parsed, bash_executable="definitely-not-used")

        self.assertEqual(checked.status, ResponseStatus.TRUNCATION)
        self.assertEqual(checked.detail, parsed.detail)
        self.assertIsNone(checked.return_code)

    def test_missing_bash_is_a_check_failure(self) -> None:
        result = check_syntax(
            parse_response("echo ok"),
            bash_executable="/definitely/missing/bash",
        )
        self.assertEqual(result.status, ResponseStatus.CHECK_FAILURE)

    def test_syntax_result_is_immutable(self) -> None:
        result = check_syntax(parse_response("```python\npass\n```"))
        with self.assertRaises(FrozenInstanceError):
            result.status = ResponseStatus.SYNTAX_FAILURE  # type: ignore[misc]

    def test_requires_parsed_response_and_positive_timeout(self) -> None:
        with self.assertRaises(TypeError):
            check_syntax("echo ok")  # type: ignore[arg-type]
        parsed = parse_response("echo ok")
        for value in (0, -1, True, "1", float("nan"), float("inf")):
            with self.subTest(timeout=value):
                with self.assertRaises(ValueError):
                    check_syntax(parsed, timeout_seconds=value)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
