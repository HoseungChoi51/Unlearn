from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cbds.development_candidate_protocol import (  # noqa: E402
    DEVELOPMENT_CANDIDATE_FIXTURE_IDENTITY_FD,
    DEVELOPMENT_CANDIDATE_MAXIMUM_CPU_TIME_USEC,
    DEVELOPMENT_CANDIDATE_MAXIMUM_PROGRAM_BYTES,
    DEVELOPMENT_CANDIDATE_MAXIMUM_STREAM_CAP_BYTES,
    DEVELOPMENT_CANDIDATE_MAXIMUM_WALL_TIMEOUT_USEC,
    DEVELOPMENT_CANDIDATE_MAXIMUM_WORKSPACE_SNAPSHOT_BYTES,
    DEVELOPMENT_CANDIDATE_MINIMUM_CPU_TIME_USEC,
    DEVELOPMENT_CANDIDATE_MINIMUM_WALL_TIMEOUT_USEC,
    DEVELOPMENT_CANDIDATE_PROGRAM_FD,
    DEVELOPMENT_CANDIDATE_PROTOCOL_VERSION,
    DEVELOPMENT_CANDIDATE_REQUEST_BYTES,
    DEVELOPMENT_CANDIDATE_REQUEST_MAGIC,
    DEVELOPMENT_CANDIDATE_RESULT_BYTES,
    DEVELOPMENT_CANDIDATE_RESULT_HASHED_PREFIX_BYTES,
    DEVELOPMENT_CANDIDATE_RESULT_MAGIC,
    DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_FD,
    DevelopmentCandidateFlag,
    DevelopmentCandidateOutcome,
    DevelopmentCandidateRequest,
    encode_development_candidate_request,
)
from cbds.development_reviewed_bash_fixture import (  # noqa: E402
    FROZEN_REVIEWED_BASH_PROGRAM,
    FROZEN_REVIEWED_FIXTURE_DEFINITION_SHA256,
    FROZEN_REVIEWED_INVOCATION_SHA256,
    FROZEN_REVIEWED_PROGRAM_SHA256,
)
from cbds.development_reviewed_bash_policy import (  # noqa: E402
    DEVELOPMENT_REVIEWED_BASH_CHILD_FSIZE_MAX_BYTES,
)
from cbds.development_candidate_workspace_snapshot import (  # noqa: E402
    DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_DEPTH,
    DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_ENTRIES,
    DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_PATH_BYTES,
    DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_REGULAR_BYTES,
    DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_SYMLINK_TARGET_BYTES,
    DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_TOTAL_PAYLOAD_BYTES,
)


SOURCE_PATH = ROOT / "native" / "cbds-development-candidate-supervisor.c"


def _source() -> str:
    return SOURCE_PATH.read_text(encoding="utf-8")


def _digest(label: str) -> bytes:
    return sha256(label.encode("ascii")).digest()


def _request() -> DevelopmentCandidateRequest:
    return DevelopmentCandidateRequest(
        program_bytes=17,
        wall_timeout_usec=1_000_000,
        cpu_time_limit_usec=500_000,
        stdout_cap_bytes=1024,
        stderr_cap_bytes=1024,
        workspace_snapshot_cap_bytes=4096,
        nonce=bytes(range(1, 33)),
        invocation_sha256=_digest("invocation"),
        program_sha256=_digest("program"),
        fixture_definition_sha256=_digest("fixture"),
        workspace_baseline_sha256=_digest("baseline"),
        runtime_snapshot_sha256=_digest("runtime"),
        allowed_tools_sha256=_digest("tools"),
        policy_sha256=_digest("policy"),
    )


def _numeric_define(source: str, name: str) -> int:
    match = re.search(
        rf"^#define\s+{re.escape(name)}\s+\(?([0-9]+)(?:U|UL|ULL)?",
        source,
        flags=re.MULTILINE,
    )
    if match is None:
        raise AssertionError(f"missing numeric define {name}")
    return int(match.group(1))


class DevelopmentCandidateNativeSourceTests(unittest.TestCase):
    def test_protocol_dimensions_descriptor_roles_and_limits_match(self) -> None:
        source = _source()
        expected = {
            "REQUEST_BYTES": DEVELOPMENT_CANDIDATE_REQUEST_BYTES,
            "RESULT_BYTES": DEVELOPMENT_CANDIDATE_RESULT_BYTES,
            "RESULT_HASHED_PREFIX_BYTES": (
                DEVELOPMENT_CANDIDATE_RESULT_HASHED_PREFIX_BYTES
            ),
            "PROTOCOL_VERSION": DEVELOPMENT_CANDIDATE_PROTOCOL_VERSION,
            "PROGRAM_FD": DEVELOPMENT_CANDIDATE_PROGRAM_FD,
            "FIXTURE_IDENTITY_FD": DEVELOPMENT_CANDIDATE_FIXTURE_IDENTITY_FD,
            "WORKSPACE_SNAPSHOT_FD": DEVELOPMENT_CANDIDATE_WORKSPACE_SNAPSHOT_FD,
            "MIN_WALL_TIMEOUT_USEC": (
                DEVELOPMENT_CANDIDATE_MINIMUM_WALL_TIMEOUT_USEC
            ),
            "MAX_WALL_TIMEOUT_USEC": (
                DEVELOPMENT_CANDIDATE_MAXIMUM_WALL_TIMEOUT_USEC
            ),
            "MIN_CPU_TIME_USEC": DEVELOPMENT_CANDIDATE_MINIMUM_CPU_TIME_USEC,
            "MAX_CPU_TIME_USEC": DEVELOPMENT_CANDIDATE_MAXIMUM_CPU_TIME_USEC,
        }
        for name, value in expected.items():
            with self.subTest(name=name):
                self.assertEqual(_numeric_define(source, name), value)
        self.assertIn(
            "#define MAX_PROGRAM_BYTES (64U * 1024U)", source
        )
        self.assertIn(
            "#define MAX_STREAM_CAP_BYTES (1024U * 1024U)", source
        )
        self.assertIn(
            "#define MAX_WORKSPACE_SNAPSHOT_BYTES (64U * 1024U * 1024U)",
            source,
        )
        self.assertEqual(DEVELOPMENT_CANDIDATE_MAXIMUM_PROGRAM_BYTES, 64 * 1024)
        self.assertEqual(
            DEVELOPMENT_CANDIDATE_MAXIMUM_STREAM_CAP_BYTES, 1024 * 1024
        )
        self.assertEqual(
            DEVELOPMENT_CANDIDATE_MAXIMUM_WORKSPACE_SNAPSHOT_BYTES,
            64 * 1024 * 1024,
        )
        self.assertEqual(
            DEVELOPMENT_REVIEWED_BASH_CHILD_FSIZE_MAX_BYTES,
            1024 * 1024,
        )
        self.assertIn(
            "#define CHILD_FSIZE_MAX_BYTES (1024U * 1024U)", source
        )

    def test_every_request_and_result_offset_matches_the_python_protocol(self) -> None:
        import cbds.development_candidate_protocol as protocol  # noqa: PLC0415

        source = _source()
        mappings = {
            "REQUEST_OFFSET_VERSION": "DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_VERSION",
            "REQUEST_OFFSET_RESERVED_U32": (
                "DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_RESERVED_U32"
            ),
            "REQUEST_OFFSET_PROGRAM_BYTES": (
                "DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_PROGRAM_BYTES"
            ),
            "REQUEST_OFFSET_WALL_TIMEOUT_USEC": (
                "DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_WALL_TIMEOUT_USEC"
            ),
            "REQUEST_OFFSET_CPU_TIME_LIMIT_USEC": (
                "DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_CPU_TIME_LIMIT_USEC"
            ),
            "REQUEST_OFFSET_STDOUT_CAP_BYTES": (
                "DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_STDOUT_CAP_BYTES"
            ),
            "REQUEST_OFFSET_STDERR_CAP_BYTES": (
                "DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_STDERR_CAP_BYTES"
            ),
            "REQUEST_OFFSET_WORKSPACE_SNAPSHOT_CAP_BYTES": (
                "DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_WORKSPACE_SNAPSHOT_CAP_BYTES"
            ),
            "REQUEST_OFFSET_NONCE": "DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_NONCE",
            "REQUEST_OFFSET_INVOCATION_SHA256": (
                "DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_INVOCATION_SHA256"
            ),
            "REQUEST_OFFSET_PROGRAM_SHA256": (
                "DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_PROGRAM_SHA256"
            ),
            "REQUEST_OFFSET_FIXTURE_DEFINITION_SHA256": (
                "DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_FIXTURE_DEFINITION_SHA256"
            ),
            "REQUEST_OFFSET_WORKSPACE_BASELINE_SHA256": (
                "DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_WORKSPACE_BASELINE_SHA256"
            ),
            "REQUEST_OFFSET_RUNTIME_SNAPSHOT_SHA256": (
                "DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_RUNTIME_SNAPSHOT_SHA256"
            ),
            "REQUEST_OFFSET_ALLOWED_TOOLS_SHA256": (
                "DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_ALLOWED_TOOLS_SHA256"
            ),
            "REQUEST_OFFSET_POLICY_SHA256": (
                "DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_POLICY_SHA256"
            ),
            "REQUEST_OFFSET_RESERVED": "DEVELOPMENT_CANDIDATE_REQUEST_OFFSET_RESERVED",
            "RESULT_OFFSET_VERSION": "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_VERSION",
            "RESULT_OFFSET_OUTCOME": "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_OUTCOME",
            "RESULT_OFFSET_PROCESS_STATUS": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_PROCESS_STATUS"
            ),
            "RESULT_OFFSET_CHILD_EXIT_CODE": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_CHILD_EXIT_CODE"
            ),
            "RESULT_OFFSET_CHILD_SIGNAL": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_CHILD_SIGNAL"
            ),
            "RESULT_OFFSET_FLAGS": "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_FLAGS",
            "RESULT_OFFSET_STDOUT_OBSERVED": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_STDOUT_OBSERVED"
            ),
            "RESULT_OFFSET_STDERR_OBSERVED": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_STDERR_OBSERVED"
            ),
            "RESULT_OFFSET_WAIT4_USER_CPU_USEC": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WAIT4_USER_CPU_USEC"
            ),
            "RESULT_OFFSET_WAIT4_SYS_CPU_USEC": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WAIT4_SYS_CPU_USEC"
            ),
            "RESULT_OFFSET_WALL_USEC": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WALL_USEC"
            ),
            "RESULT_OFFSET_DESCENDANTS_REAPED": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_DESCENDANTS_REAPED"
            ),
            "RESULT_OFFSET_RESERVED_U32": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_RESERVED_U32"
            ),
            "RESULT_OFFSET_WORKSPACE_SNAPSHOT_BYTES": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WORKSPACE_SNAPSHOT_BYTES"
            ),
            "RESULT_OFFSET_CUMULATIVE_CPU_USEC": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_CUMULATIVE_CPU_USEC"
            ),
            "RESULT_OFFSET_REQUEST_SHA256": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_REQUEST_SHA256"
            ),
            "RESULT_OFFSET_NONCE": "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_NONCE",
            "RESULT_OFFSET_INVOCATION_SHA256": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_INVOCATION_SHA256"
            ),
            "RESULT_OFFSET_PROGRAM_SHA256": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_PROGRAM_SHA256"
            ),
            "RESULT_OFFSET_FIXTURE_DEFINITION_SHA256": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_FIXTURE_DEFINITION_SHA256"
            ),
            "RESULT_OFFSET_WORKSPACE_BASELINE_SHA256": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WORKSPACE_BASELINE_SHA256"
            ),
            "RESULT_OFFSET_RUNTIME_SNAPSHOT_SHA256": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_RUNTIME_SNAPSHOT_SHA256"
            ),
            "RESULT_OFFSET_ALLOWED_TOOLS_SHA256": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_ALLOWED_TOOLS_SHA256"
            ),
            "RESULT_OFFSET_POLICY_SHA256": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_POLICY_SHA256"
            ),
            "RESULT_OFFSET_STDOUT_SHA256": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_STDOUT_SHA256"
            ),
            "RESULT_OFFSET_STDERR_SHA256": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_STDERR_SHA256"
            ),
            "RESULT_OFFSET_WORKSPACE_SNAPSHOT_SHA256": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_WORKSPACE_SNAPSHOT_SHA256"
            ),
            "RESULT_OFFSET_RESULT_SHA256": (
                "DEVELOPMENT_CANDIDATE_RESULT_OFFSET_RESULT_SHA256"
            ),
        }
        for native_name, python_name in mappings.items():
            with self.subTest(native=native_name):
                self.assertEqual(
                    _numeric_define(source, native_name),
                    getattr(protocol, python_name),
                )

    def test_magic_outcomes_flags_and_precedence_are_exact(self) -> None:
        source = _source()
        self.assertIn("'C', 'B', 'D', 'S', 'B', 'R', 'Q', '2'", source)
        self.assertIn("'C', 'B', 'D', 'S', 'B', 'R', 'S', '2'", source)
        self.assertEqual(DEVELOPMENT_CANDIDATE_REQUEST_MAGIC, b"CBDSBRQ2")
        self.assertEqual(DEVELOPMENT_CANDIDATE_RESULT_MAGIC, b"CBDSBRS2")
        for outcome in DevelopmentCandidateOutcome:
            with self.subTest(outcome=outcome.name):
                self.assertRegex(
                    source,
                    rf"OUTCOME_{outcome.name}\s*=\s*{int(outcome)}(?:,|\n)",
                )
        for flag in DevelopmentCandidateFlag:
            shift = flag.value.bit_length() - 1
            with self.subTest(flag=flag.name):
                self.assertRegex(
                    source,
                    rf"FLAG_{flag.name}\s*=\s*1U\s*<<\s*{shift}",
                )
        precedence_body = source[
            source.index("static uint32_t classify_outcome") :
            source.index("static int write_result")
        ]
        ordered = (
            "FLAG_WORKSPACE_SNAPSHOT_OVERFLOW",
            "FLAG_STDOUT_OVERFLOW",
            "FLAG_STDERR_OVERFLOW",
            "FLAG_CPU_LIMIT_REACHED",
            "FLAG_WALL_LIMIT_REACHED",
        )
        positions = tuple(precedence_body.index(name) for name in ordered)
        self.assertEqual(positions, tuple(sorted(positions)))

    def test_execution_surface_is_one_fixed_argv_and_stays_nonauthorizing(self) -> None:
        source = _source()
        self.assertEqual(
            source.count('execve("/usr/bin/bash", argv, environment)'), 1
        )
        for literal in (
            '(char *)"/usr/bin/bash"',
            '(char *)"--noprofile"',
            '(char *)"--norc"',
            '(char *)"/proc/self/fd/3"',
            'chdir("/workspace")',
            "prctl(PR_SET_DUMPABLE, 0L",
            "prctl(PR_SET_NO_NEW_PRIVS, 1L",
            "wait4(-1",
            "kill(-1, SIGKILL)",
            'opendir("/proc")',
            "_SC_CLK_TCK",
        ):
            with self.subTest(literal=literal):
                self.assertIn(literal, source)
        self.assertNotIn("system(", source)
        self.assertNotIn("popen(", source)
        self.assertNotIn("posix_spawn", source)
        self.assertRegex(
            source,
            r"flags\s*\|=\s*FLAG_CHILD_NO_NEW_PRIVS\s*\|\s*"
            r"FLAG_CHILD_PREEXEC_DUMPABLE_DISABLED\s*\|\s*"
            r"FLAG_CHILD_SECCOMP_INSTALLED",
        )
        self.assertIn("install_reviewed_bash_seccomp()", source)
        self.assertIn("SECCOMP_RET_ERRNO", source)
        self.assertIn("SECCOMP_RET_KILL_PROCESS", source)
        write_result = source[
            source.index("static int write_result") : source.index("int main(void)")
        ]
        self.assertIn("RESULT_OFFSET_OUTCOME, outcome", write_result)
        self.assertIn(
            "infrastructure_error ? OUTCOME_SUPERVISOR_ERROR", source
        )
        for unavailable in (
            "FLAG_RUNTIME_SNAPSHOT_VALIDATED",
            "FLAG_WORKSPACE_BASELINE_VALIDATED",
            "FLAG_ALLOWED_TOOLS_VALIDATED",
            "FLAG_POLICY_VALIDATED",
        ):
            with self.subTest(unavailable=unavailable):
                self.assertNotRegex(
                    source, rf"flags\s*\|=\s*{unavailable}"
                )
        self.assertIn(
            "Exec may reset dumpability; this records only the pre-exec state.",
            source,
        )
        for denied in (
            "SYS_socket",
            "SYS_connect",
            "SYS_unshare",
            "SYS_setns",
            "SYS_mount",
            "SYS_ptrace",
            "SYS_bpf",
            "SYS_capset",
            "SYS_init_module",
            "SYS_io_uring_setup",
        ):
            with self.subTest(denied=denied):
                self.assertIn(f"DENY_SYSCALL({denied})", source)
        for false_authority in (
            "arbitrary candidates",
            "runtime-data closure",
            "exact-tool enforcement",
            "general Bash policy",
            "claim authority",
        ):
            with self.subTest(false_authority=false_authority):
                self.assertIn(false_authority, source)

    def test_native_admits_only_the_one_frozen_reviewed_program_and_fixture(self) -> None:
        source = _source()
        for native_name, expected in (
            ("REVIEWED_PROGRAM_SHA256", FROZEN_REVIEWED_PROGRAM_SHA256),
            ("REVIEWED_INVOCATION_SHA256", FROZEN_REVIEWED_INVOCATION_SHA256),
            (
                "REVIEWED_FIXTURE_DEFINITION_SHA256",
                FROZEN_REVIEWED_FIXTURE_DEFINITION_SHA256,
            ),
        ):
            with self.subTest(native_name=native_name):
                match = re.search(
                    rf"static const unsigned char {native_name}\[32\] = \{{(.*?)\}};",
                    source,
                    flags=re.DOTALL,
                )
                if match is None:
                    self.fail(f"missing native reviewed identity {native_name}")
                native_bytes = bytes(
                    int(value, 16)
                    for value in re.findall(r"0x([0-9a-f]{2})U", match.group(1))
                )
                self.assertEqual(native_bytes.hex(), expected)
        self.assertEqual(len(FROZEN_REVIEWED_BASH_PROGRAM), 153)
        self.assertIn(
            "request->program_bytes != sizeof(REVIEWED_PROGRAM) - 1U", source
        )
        self.assertGreaterEqual(
            source.count(
                "memcmp(program, REVIEWED_PROGRAM, sizeof(REVIEWED_PROGRAM) - 1U)"
            ),
            2,
        )
        self.assertIn("REVIEWED_INVOCATION_SHA256, 32U", source)
        self.assertIn("REVIEWED_FIXTURE_DEFINITION_SHA256, 32U", source)
        self.assertIn("descriptor_content_is_immutable(PROGRAM_FD)", source)
        self.assertIn(
            "descriptor_content_is_immutable(FIXTURE_IDENTITY_FD)", source
        )
        self.assertIn("F_GET_SEALS", source)
        self.assertIn("ST_RDONLY", source)
        self.assertIn('open("/cbds-program.sh"', source)
        self.assertIn("lseek(PROGRAM_FD, 0, SEEK_SET)", source)

    def test_fixture_identity_and_snapshot_wire_contract_are_explicit(self) -> None:
        source = _source()
        self.assertIn(
            "descriptor 4 as the exact 32-byte fixture-definition identity token",
            source,
        )
        self.assertIn("descriptor_is_read_only_regular(FIXTURE_IDENTITY_FD, 32U)", source)
        self.assertIn("REQUEST_OFFSET_FIXTURE_DEFINITION_SHA256", source)
        self.assertIn('magic[8]="CBDSWSN1"', source)
        self.assertIn("SNAPSHOT_DIRECTORY = 1", source)
        self.assertIn("SNAPSHOT_REGULAR = 2", source)
        self.assertIn("SNAPSHOT_SYMLINK = 3", source)
        self.assertIn("AT_SYMLINK_NOFOLLOW", source)
        self.assertIn("O_NOFOLLOW", source)
        self.assertIn("qsort(names->items", source)
        self.assertIn("request.workspace_snapshot_cap_bytes + 1U", source)
        self.assertIn("post-run output-projection archive", source)
        self.assertIn(
            "independently rechecks the full descriptor-bound input baseline",
            source,
        )
        self.assertIn(
            'if (depth == 0U && strcmp(names.items[index], "input") == 0)',
            source,
        )
        self.assertEqual(
            source.count(
                'depth == 0U && strcmp(names.items[index], "input") == 0'
            ),
            1,
        )
        self.assertNotIn('strcmp(names.items[index], "output") == 0', source)
        for name, expected in (
            ("SNAPSHOT_MAX_DEPTH", DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_DEPTH),
            (
                "SNAPSHOT_MAX_ENTRIES",
                DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_ENTRIES,
            ),
            (
                "SNAPSHOT_MAX_PATH_BYTES",
                DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_PATH_BYTES,
            ),
            (
                "SNAPSHOT_MAX_SYMLINK_TARGET_BYTES",
                DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_SYMLINK_TARGET_BYTES,
            ),
        ):
            with self.subTest(snapshot_limit=name):
                self.assertEqual(_numeric_define(source, name), expected)
        self.assertEqual(
            DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_REGULAR_BYTES,
            1024 * 1024,
        )
        self.assertEqual(
            DEVELOPMENT_CANDIDATE_WORKSPACE_MAXIMUM_TOTAL_PAYLOAD_BYTES,
            16 * 1024 * 1024,
        )
        self.assertIn(
            "#define SNAPSHOT_MAX_REGULAR_BYTES (1024U * 1024U)", source
        )
        self.assertIn(
            "#define SNAPSHOT_MAX_TOTAL_PAYLOAD_BYTES (16U * 1024U * 1024U)",
            source,
        )
        self.assertIn("snapshot_force_overflow(snapshot)", source)

    def test_builtin_sha_and_classification_vectors_compile_and_run(self) -> None:
        compiler = shutil.which("gcc")
        if compiler is None:
            self.skipTest("gcc is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness = root / "harness.c"
            binary = root / "harness"
            expected = ",".join(f"0x{value:02x}" for value in sha256(b"abc").digest())
            harness.write_text(
                "#define main candidate_supervisor_main\n"
                f'#include "{SOURCE_PATH}"\n'
                "#undef main\n"
                "int main(void) {\n"
                "  unsigned char digest[32];\n"
                f"  static const unsigned char expected[32] = {{{expected}}};\n"
                '  sha256_bytes((const unsigned char *)"abc", 3U, digest);\n'
                "  if (memcmp(digest, expected, 32U) != 0) return 1;\n"
                "  sha256_bytes(REVIEWED_PROGRAM, sizeof(REVIEWED_PROGRAM) - 1U, digest);\n"
                "  if (sizeof(REVIEWED_PROGRAM) - 1U != 153U ||\n"
                "      memcmp(digest, REVIEWED_PROGRAM_SHA256, 32U) != 0) return 5;\n"
                "  {\n"
                "    pid_t child = fork(); int status = 0;\n"
                "    if (child < 0) return 8;\n"
                "    if (child == 0) {\n"
                "      struct rlimit limit;\n"
                "      if (install_reviewed_child_resource_limits() != 0 ||\n"
                "          getrlimit(RLIMIT_FSIZE, &limit) != 0 ||\n"
                "          limit.rlim_cur != CHILD_FSIZE_MAX_BYTES ||\n"
                "          limit.rlim_max != CHILD_FSIZE_MAX_BYTES) _exit(30);\n"
                "      _exit(0);\n"
                "    }\n"
                "    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||\n"
                "        WEXITSTATUS(status) != 0) return 9;\n"
                "  }\n"
                "  if (classify_outcome(\n"
                "      FLAG_WORKSPACE_SNAPSHOT_OVERFLOW | FLAG_STDOUT_OVERFLOW |\n"
                "      FLAG_STDERR_OVERFLOW | FLAG_CPU_LIMIT_REACHED |\n"
                "      FLAG_WALL_LIMIT_REACHED, PROCESS_EXITED, 0) !=\n"
                "      OUTCOME_WORKSPACE_SNAPSHOT_OVERFLOW) return 2;\n"
                "  if (classify_outcome(\n"
                "      FLAG_STDOUT_OVERFLOW | FLAG_CPU_LIMIT_REACHED,\n"
                "      PROCESS_EXITED, 0) != OUTCOME_STDOUT_OVERFLOW) return 3;\n"
                "  if (classify_outcome(\n"
                "      FLAG_CPU_LIMIT_REACHED | FLAG_WALL_LIMIT_REACHED,\n"
                "      PROCESS_EXITED, 0) != OUTCOME_CPU_LIMIT) return 4;\n"
                "  {\n"
                "    pid_t child = fork(); int status = 0;\n"
                "    if (child < 0) return 6;\n"
                "    if (child == 0) {\n"
                "      if (prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0 ||\n"
                "          install_reviewed_bash_seccomp() != 0) _exit(20);\n"
                "      errno = 0;\n"
                "      if (syscall(SYS_socket, 2, 1, 0) != -1 || errno != EPERM) _exit(21);\n"
                "      errno = 0;\n"
                "      if (syscall(SYS_unshare, 0) != -1 || errno != EPERM) _exit(22);\n"
                "      if (syscall(SYS_getpid) <= 0) _exit(23);\n"
                "      _exit(0);\n"
                "    }\n"
                "    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||\n"
                "        WEXITSTATUS(status) != 0) return 7;\n"
                "  }\n"
                "  return 0;\n"
                "}\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                (
                    compiler,
                    "-std=gnu17",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-static-pie",
                    str(harness),
                    "-o",
                    str(binary),
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr.decode("utf-8", errors="replace"),
            )
            run = subprocess.run(
                (str(binary),),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                check=False,
            )
            self.assertEqual(run.returncode, 0)
            self.assertEqual(run.stdout, b"")
            self.assertEqual(run.stderr, b"")

    def test_output_projection_skips_unreadable_top_level_input_subtree(self) -> None:
        compiler = shutil.which("gcc")
        if compiler is None:
            self.skipTest("gcc is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            input_tree = workspace / "input" / "tree"
            output = workspace / "output"
            input_tree.mkdir(parents=True)
            output.mkdir()
            locked = input_tree / "locked-secret.txt"
            locked.write_bytes(b"must-not-enter-the-output-projection\n")
            locked.chmod(0)
            (output / "paths.txt").write_bytes(b"visible.txt\n")

            harness = root / "snapshot-harness.c"
            binary = root / "snapshot-harness"
            harness.write_text(
                "#define main candidate_supervisor_main\n"
                f'#include "{SOURCE_PATH}"\n'
                "#undef main\n"
                "int main(int argc, char **argv) {\n"
                "  struct snapshot_buffer snapshot; struct stat status; int fd; int result;\n"
                "  if (argc != 2) return 10;\n"
                "  memset(&snapshot, 0, sizeof(snapshot));\n"
                "  snapshot.ceiling = 4096U; snapshot.bytes = malloc(snapshot.ceiling);\n"
                "  if (snapshot.bytes == NULL) return 11;\n"
                "  fd = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);\n"
                "  if (fd < 0 || fstat(fd, &status) != 0) return 12;\n"
                '  result = snapshot_directory(&snapshot, fd, "", &status, 0U);\n'
                "  if (close(fd) != 0 || result != 0 || snapshot.overflow) return 13;\n"
                "  if (snapshot.entries != 3U || snapshot.total_payload_bytes != 12U) return 14;\n"
                '  if (memmem(snapshot.bytes, snapshot.used, "input", 5U) != NULL) return 15;\n'
                '  if (memmem(snapshot.bytes, snapshot.used, "locked-secret", 13U) != NULL) return 16;\n'
                '  if (memmem(snapshot.bytes, snapshot.used, "output", 6U) == NULL ||\n'
                '      memmem(snapshot.bytes, snapshot.used, "paths.txt", 9U) == NULL ||\n'
                '      memmem(snapshot.bytes, snapshot.used, "visible.txt\\n", 12U) == NULL) return 17;\n'
                "  free(snapshot.bytes); return 0;\n"
                "}\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                (
                    compiler,
                    "-std=gnu17",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-static-pie",
                    str(harness),
                    "-o",
                    str(binary),
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr.decode("utf-8", errors="replace"),
            )
            run = subprocess.run(
                (str(binary), str(workspace)),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                check=False,
            )
            self.assertEqual(run.returncode, 0)
            self.assertEqual(run.stdout, b"")
            self.assertEqual(run.stderr, b"")

    def test_native_source_builds_static_pie_strictly_and_refuses_non_pid1(self) -> None:
        compiler = shutil.which("gcc")
        if compiler is None:
            self.skipTest("gcc is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "cbds-development-candidate-supervisor"
            completed = subprocess.run(
                (
                    compiler,
                    "-std=gnu17",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-static-pie",
                    "-Wl,-z,relro,-z,now,-z,noexecstack",
                    str(SOURCE_PATH),
                    "-o",
                    str(binary),
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr.decode("utf-8", errors="replace"),
            )
            request_frame = encode_development_candidate_request(_request())
            self.assertEqual(
                struct.unpack_from("<Q", request_frame, 16)[0], 17
            )
            run = subprocess.run(
                (str(binary),),
                input=request_frame,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                check=False,
            )
            self.assertEqual(run.returncode, 111)
            self.assertEqual(run.stdout, b"")
            self.assertEqual(run.stderr, b"")


if __name__ == "__main__":
    unittest.main()
