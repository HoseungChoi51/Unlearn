"""Reviewed seven-tool Bash canary for compressed archive roundtrips.

The fixed literal is public-development feasibility evidence only.  It is not
a caller-selected candidate API, production sandbox, scored evaluation,
model-selection input, or evidence of transient verification history.
"""

from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_compressed_archive_roundtrip_verify as archive  # noqa: E402
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)


_HAND_AUTHORED_BASH = r"""
set -euo pipefail

export LC_ALL=C
export TZ=UTC
umask 022
unset TAR_OPTIONS POSIXLY_CORRECT GZIP BZIP BZIP2 XZ_DEFAULTS XZ_OPT

compression_format=${1:?compression format required}
verification_policy=${2:?verification policy required}
case $compression_format in
    gzip|bzip2|xz|none) ;;
    *) exit 64 ;;
esac
case $verification_policy in
    archive-digest|member-digests|roundtrip-bytes|roundtrip-bytes-and-modes|strict-all) ;;
    *) exit 65 ;;
esac

declare -A mode_by_relative=()
manifest_members=()
while IFS= read -r -d '' relative; do
    IFS= read -r -d '' mode || exit 66
    [[ -n $relative && $mode =~ ^0[0-7]{3}$ ]]
    [[ -z ${mode_by_relative["$relative"]+present} ]]
    [[ -f input/source/$relative && ! -L input/source/$relative ]]
    (( (8#$mode & 0400) != 0 ))
    mode_by_relative["$relative"]=$mode
    manifest_members+=("$relative")
done < input/members.nul
((${#manifest_members[@]} > 0))

members=()
mapfile -d '' -t members < <(
    printf '%s\0' "${manifest_members[@]}" | sort -z --
)
((${#members[@]} == ${#manifest_members[@]}))

case $compression_format in
    gzip) archive_path=output/package.tar.gz ;;
    bzip2) archive_path=output/package.tar.bz2 ;;
    xz) archive_path=output/package.tar.xz ;;
    none) archive_path=output/package.tar ;;
esac

mkdir -p -- output/roundtrip

tar_arguments=(
    --format=ustar
    --owner=0
    --group=0
    --numeric-owner
    --mtime=@0
    --hard-dereference
    --no-recursion
    --null
    --verbatim-files-from
    -C input/source
)

case $compression_format in
    gzip)
        printf '%s\0' "${members[@]}" |
            tar "${tar_arguments[@]}" -cf - -T - |
            gzip -n -9 -c > "$archive_path"
        ;;
    bzip2)
        printf '%s\0' "${members[@]}" |
            tar "${tar_arguments[@]}" -cf - -T - |
            bzip2 -9 -c > "$archive_path"
        ;;
    xz)
        printf '%s\0' "${members[@]}" |
            tar "${tar_arguments[@]}" -cf - -T - |
            xz --format=xz --check=crc64 -6 -c > "$archive_path"
        ;;
    none)
        printf '%s\0' "${members[@]}" |
            tar "${tar_arguments[@]}" -cf "$archive_path" -T -
        ;;
esac

decode_archive() {
    case $compression_format in
        gzip) gzip -cd -- "$archive_path" ;;
        bzip2) bzip2 -cd -- "$archive_path" ;;
        xz) xz -cd -- "$archive_path" ;;
        none) while IFS= read -r -d '' chunk; do printf '%s\0' "$chunk"; done < "$archive_path" ;;
    esac
}

case $compression_format in
    gzip)
        gzip -cd -- "$archive_path" |
            tar --no-same-owner -xpf - -C output/roundtrip
        ;;
    bzip2)
        bzip2 -cd -- "$archive_path" |
            tar --no-same-owner -xpf - -C output/roundtrip
        ;;
    xz)
        xz -cd -- "$archive_path" |
            tar --no-same-owner -xpf - -C output/roundtrip
        ;;
    none)
        tar --no-same-owner -xpf "$archive_path" -C output/roundtrip
        ;;
esac

archive_sha=
IFS=' ' read -r archive_sha _ < <(sha256sum -- "$archive_path")
[[ $archive_sha =~ ^[0-9a-f]{64}$ ]]
member_count=${#members[@]}

exec 3> output/verification.tsv
case $verification_policy in
    archive-digest)
        printf 'archive\t%s\t%s\t%s\n' \
            "$compression_format" "$archive_path" "$archive_sha" >&3
        ;;
    member-digests)
        printf 'members\t%s\n' "$member_count" >&3
        for relative in "${members[@]}"; do
            member_sha=
            IFS=' ' read -r member_sha _ < <(
                decode_archive |
                    tar -xOf - -- "$relative" |
                    sha256sum
            )
            printf 'member\t%s\t%s\n' "$relative" "$member_sha" >&3
        done
        ;;
    roundtrip-bytes)
        printf 'roundtrip-bytes\t%s\n' "$member_count" >&3
        for relative in "${members[@]}"; do
            source_sha=
            roundtrip_sha=
            IFS=' ' read -r source_sha _ < <(
                sha256sum -- "input/source/$relative"
            )
            IFS=' ' read -r roundtrip_sha _ < <(
                sha256sum -- "output/roundtrip/$relative"
            )
            printf 'file\t%s\t%s\t%s\n' \
                "$relative" "$source_sha" "$roundtrip_sha" >&3
        done
        ;;
    roundtrip-bytes-and-modes)
        printf 'roundtrip-bytes-and-modes\t%s\n' "$member_count" >&3
        for relative in "${members[@]}"; do
            source_sha=
            roundtrip_sha=
            IFS=' ' read -r source_sha _ < <(
                sha256sum -- "input/source/$relative"
            )
            IFS=' ' read -r roundtrip_sha _ < <(
                sha256sum -- "output/roundtrip/$relative"
            )
            printf 'file\t%s\t%s\t%s\t%s\n' \
                "$relative" "${mode_by_relative["$relative"]}" \
                "$source_sha" "$roundtrip_sha" >&3
        done
        ;;
    strict-all)
        raw_sha=
        IFS=' ' read -r raw_sha _ < <(decode_archive | sha256sum)
        printf 'strict\t%s\t%s\t%s\t%s\t%s\n' \
            "$compression_format" "$archive_path" "$archive_sha" \
            "$raw_sha" "$member_count" >&3
        for relative in "${members[@]}"; do
            source_sha=
            member_sha=
            roundtrip_sha=
            IFS=' ' read -r source_sha _ < <(
                sha256sum -- "input/source/$relative"
            )
            IFS=' ' read -r member_sha _ < <(
                decode_archive |
                    tar -xOf - -- "$relative" |
                    sha256sum
            )
            IFS=' ' read -r roundtrip_sha _ < <(
                sha256sum -- "output/roundtrip/$relative"
            )
            printf 'file\t%s\t%s\t%s\t%s\t%s\n' \
                "$relative" "${mode_by_relative["$relative"]}" \
                "$source_sha" "$member_sha" "$roundtrip_sha" >&3
        done
        ;;
esac
exec 3>&-
"""

_HAND_AUTHORED_BASH_SHA256 = (
    "27459a001319b29147d5960a5337234ecd89e12e25b09f2a86d3c85b90591a42"
)


class CompressedArchiveRoundtripVerifyBashCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = archive.build_compressed_archive_roundtrip_verify_tasks()
        cls.bundles = {
            (task.task_id, profile.profile_id):
            archive.build_compressed_archive_roundtrip_verify_fixture_bundle(
                task, profile
            )
            for task in cls.tasks
            for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        }
        cls.bash = shutil.which("bash")
        if cls.bash is None:
            raise unittest.SkipTest("bash is unavailable")

    def test_literal_hash_and_declared_tool_boundary(self) -> None:
        self.assertEqual(
            sha256(_HAND_AUTHORED_BASH.encode("utf-8")).hexdigest(),
            _HAND_AUTHORED_BASH_SHA256,
        )
        self.assertEqual(
            archive.COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ALLOWED_TOOLS,
            ("bzip2", "gzip", "mkdir", "sha256sum", "sort", "tar", "xz"),
        )
        self.assertIn("unset TAR_OPTIONS POSIXLY_CORRECT", _HAND_AUTHORED_BASH)
        self.assertNotIn("find ", _HAND_AUTHORED_BASH)
        self.assertNotIn("stat ", _HAND_AUTHORED_BASH)
        self.assertNotIn("python", _HAND_AUTHORED_BASH.lower())

    def test_reviewed_literal_solves_all_100_bundles_with_exact_path(self) -> None:
        with tempfile.TemporaryDirectory() as parent_text:
            parent = Path(parent_text)
            tool_root = parent / "tools"
            tool_root.mkdir(mode=0o755)
            for tool in archive.COMPRESSED_ARCHIVE_ROUNDTRIP_VERIFY_ALLOWED_TOOLS:
                executable = shutil.which(tool)
                if executable is None:
                    self.skipTest(f"required canary tool is unavailable: {tool}")
                (tool_root / tool).symlink_to(executable)

            environment = {
                "HOME": str(parent / "home"),
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": str(tool_root),
                "TZ": "UTC",
            }
            (parent / "home").mkdir(mode=0o755)
            ordinal = 0
            for task in self.tasks:
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
                    bundle = self.bundles[(task.task_id, profile.profile_id)]
                    workspace = parent / f"workspace-{ordinal:03d}"
                    ordinal += 1
                    handle = (
                        archive.materialize_compressed_archive_roundtrip_verify_fixture(
                            task, profile, bundle, workspace
                        )
                    )
                    try:
                        completed = subprocess.run(
                            [
                                self.bash,
                                "-c",
                                _HAND_AUTHORED_BASH,
                                "--",
                                task.parameters.compression_format,
                                task.parameters.verification_policy,
                            ],
                            cwd=workspace,
                            env=environment,
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            timeout=30,
                            check=False,
                        )
                        with self.subTest(
                            format=task.parameters.compression_format,
                            policy=task.parameters.verification_policy,
                            profile=profile.profile_id,
                        ):
                            self.assertEqual(
                                completed.returncode,
                                0,
                                completed.stderr.decode(
                                    "utf-8", errors="replace"
                                ),
                            )
                            self.assertEqual(completed.stdout, b"")
                            self.assertTrue(
                                archive.verify_compressed_archive_roundtrip_verify_workspace(
                                    task, profile, bundle, handle
                                )
                            )
                    finally:
                        handle.close()


if __name__ == "__main__":
    unittest.main()
