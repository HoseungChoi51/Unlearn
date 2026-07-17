"""Fixed reviewed Bash feasibility canary for nested JSON migration.

Only the immutable Bash literal below is executed.  It is public
method-development feasibility evidence for one source-reviewed program, not
a caller-selected candidate API, production sandbox, scored evaluation,
model-selection input, or evidence about model quality.  Its restricted PATH
demonstrates only that this literal stays within the family's exact external
tool budget.  Final-state verification does not prove tool history, read
scope, filesystem atomicity, transient behavior, candidate exit status, or
global quiescence.
"""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_nested_json_schema_migration as migration  # noqa: E402
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)


_HAND_AUTHORED_BASH = r"""
set -euo pipefail

export LC_ALL=C
export TZ=UTC
export PYTHONHASHSEED=0
export PYTHONNOUSERSITE=1
umask 022
unset BASH_ENV CDPATH ENV GLOBIGNORE PYTHONHOME PYTHONPATH

input_shape=${1:?input shape required}
migration_policy=${2:?migration policy required}
case $input_shape in
    single-object|object-array|keyed-object-map|jsonl-objects) ;;
    *) exit 64 ;;
esac
case $migration_policy in
    rename-fields|normalize-types|lift-nested-members|drop-deprecated-members|combined-version-upgrade) ;;
    *) exit 65 ;;
esac

python3 -I -S - "$input_shape" "$migration_policy" <<'PYTHON'
import copy
import json
import os
import re
import stat
import sys
import unicodedata


INPUT = "input/documents.data"
MAX_SOURCE = 128 * 1024
MAX_DOCUMENTS = 32
MAX_DEPTH = 8
MAX_NODES = 4096
MAX_MEMBERS = 128
MAX_SCALAR_BYTES = 128
MAX_TAGS = 16
MAX_QUOTA = 1000000
MAX_DOCUMENT_OUTPUT = 8 * 1024
MAX_MANIFEST_OUTPUT = 32 * 1024
MAX_TOTAL_OUTPUT = MAX_DOCUMENTS * MAX_DOCUMENT_OUTPUT + MAX_MANIFEST_OUTPUT
SHAPES = (
    "single-object",
    "object-array",
    "keyed-object-map",
    "jsonl-objects",
)
POLICIES = (
    "rename-fields",
    "normalize-types",
    "lift-nested-members",
    "drop-deprecated-members",
    "combined-version-upgrade",
)
V1_TOP_KEYS = {
    "schema_version",
    "record_id",
    "profile",
    "tags",
    "deprecated",
}
V1_PROFILE_KEYS = {
    "display_name",
    "enabled",
    "limits",
    "contact",
    "deprecated_code",
}
V2_TOP_KEYS = {
    "schema_version",
    "record_id",
    "id",
    "profile",
    "tags",
    "deprecated",
    "email",
    "quota",
}
V2_PROFILE_KEYS = {
    "display_name",
    "name",
    "enabled",
    "limits",
    "contact",
    "deprecated_code",
}
CANONICAL_DECIMAL = re.compile(r"-?(?:0|[1-9][0-9]{0,6})\Z")


class InvalidMigration(Exception):
    pass


def fail():
    raise InvalidMigration()


def validate_string(value, nonempty=False):
    if type(value) is not str or (nonempty and not value):
        fail()
    for character in value:
        if unicodedata.category(character) in {"Cc", "Cf"}:
            fail()
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        fail()
    if len(encoded) > MAX_SCALAR_BYTES:
        fail()
    return value


def require_object(value, required, allowed):
    if type(value) is not dict:
        fail()
    keys = set(value)
    if not required <= keys or not keys <= allowed:
        fail()
    return value


def validate_enabled(value):
    if type(value) is bool:
        return value
    if type(value) is int and value in {0, 1}:
        return value
    if type(value) is str and value in {
        "true",
        "false",
        "yes",
        "no",
        "1",
        "0",
    }:
        return value
    fail()


def validate_quota(value):
    if type(value) is int:
        if abs(value) <= MAX_QUOTA:
            return value
    elif (
        type(value) is str
        and value != "-0"
        and CANONICAL_DECIMAL.fullmatch(value)
    ):
        if abs(int(value)) <= MAX_QUOTA:
            return value
    fail()


def validate_tags(value):
    if type(value) is str:
        validate_string(value)
        return value
    if type(value) is not list or len(value) > MAX_TAGS:
        fail()
    for item in value:
        validate_string(item)
    return value


def validate_v1(value):
    document = require_object(
        value,
        {"schema_version", "record_id", "profile"},
        V1_TOP_KEYS,
    )
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 1
    ):
        fail()
    validate_string(document["record_id"], nonempty=True)
    profile = require_object(
        document["profile"],
        {"display_name", "enabled"},
        V1_PROFILE_KEYS,
    )
    validate_string(profile["display_name"])
    validate_enabled(profile["enabled"])
    if "limits" in profile:
        limits = require_object(
            profile["limits"],
            {"quota"},
            {"quota"},
        )
        validate_quota(limits["quota"])
    if "contact" in profile:
        contact = require_object(
            profile["contact"],
            {"email"},
            {"email"},
        )
        validate_string(contact["email"])
    if "deprecated_code" in profile:
        validate_string(profile["deprecated_code"])
    if "tags" in document:
        validate_tags(document["tags"])
    if "deprecated" in document:
        deprecated = require_object(
            document["deprecated"],
            {"note"},
            {"note"},
        )
        validate_string(deprecated["note"])
    return document


def prebound_json(text):
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                fail()
        elif character in "]}":
            depth -= 1
            if depth < 0:
                fail()
    if in_string or escaped or depth != 0:
        fail()


def bounded_int(token):
    if len(token.lstrip("-")) > 7:
        fail()
    value = int(token)
    if abs(value) > MAX_QUOTA:
        fail()
    return value


def reject_float(_token):
    fail()


def reject_constant(_token):
    fail()


def reject_duplicate_object(pairs):
    if len(pairs) > MAX_MEMBERS:
        fail()
    result = {}
    for key, value in pairs:
        if key in result:
            fail()
        result[key] = value
    return result


def validate_json_tree(root):
    stack = [(root, 1)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            fail()
        if type(value) is dict:
            if len(value) > MAX_MEMBERS:
                fail()
            for key, item in value.items():
                validate_string(key)
                stack.append((item, depth + 1))
        elif type(value) is list:
            if len(value) > MAX_NODES:
                fail()
            for item in value:
                stack.append((item, depth + 1))
        elif type(value) is str:
            validate_string(value)
        elif value is None or type(value) in {bool, int}:
            pass
        else:
            fail()


def decode_json(payload):
    if type(payload) is not bytes or not payload:
        fail()
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        fail()
    if text.startswith("\ufeff"):
        fail()
    prebound_json(text)
    try:
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_object,
            parse_int=bounded_int,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
    except InvalidMigration:
        raise
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        fail()
    validate_json_tree(value)
    return value


def read_source():
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(INPUT, flags)
    try:
        identity = os.fstat(descriptor)
        if not stat.S_ISREG(identity.st_mode):
            fail()
        pieces = []
        remaining = MAX_SOURCE + 1
        while remaining:
            piece = os.read(descriptor, remaining)
            if not piece:
                break
            pieces.append(piece)
            remaining -= len(piece)
        payload = b"".join(pieces)
    finally:
        os.close(descriptor)
    if (
        not payload
        or len(payload) > MAX_SOURCE
        or not payload.endswith(b"\n")
    ):
        fail()
    return payload


def parse_source(payload, shape):
    if shape == "jsonl-objects":
        lines = payload[:-1].split(b"\n")
        if (
            not lines
            or len(lines) > MAX_DOCUMENTS
            or any(not line or b"\r" in line for line in lines)
        ):
            fail()
        result = []
        for index, line in enumerate(lines):
            result.append((index, None, validate_v1(decode_json(line))))
        return result

    value = decode_json(payload[:-1])
    if shape == "single-object":
        return [(0, None, validate_v1(value))]
    if shape == "object-array":
        if (
            type(value) is not list
            or not value
            or len(value) > MAX_DOCUMENTS
        ):
            fail()
        return [
            (index, None, validate_v1(document))
            for index, document in enumerate(value)
        ]
    if shape == "keyed-object-map":
        if (
            type(value) is not dict
            or not value
            or len(value) > MAX_DOCUMENTS
        ):
            fail()
        ordered = sorted(
            value.items(),
            key=lambda item: item[0].encode("utf-8"),
        )
        result = []
        for index, (key, raw_document) in enumerate(ordered):
            validate_string(key, nonempty=True)
            document = validate_v1(raw_document)
            if document["record_id"] != key:
                fail()
            result.append((index, key, document))
        return result
    fail()


def normalize_enabled(value):
    validate_enabled(value)
    if type(value) is bool:
        return value
    if type(value) is int:
        return value == 1
    return value in {"true", "yes", "1"}


def normalize_quota(value):
    validate_quota(value)
    if type(value) is int:
        return value
    return int(value)


def validate_v2(value):
    document = require_object(
        value,
        {"schema_version", "profile"},
        V2_TOP_KEYS,
    )
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 2
    ):
        fail()
    identity_fields = [
        key for key in ("record_id", "id") if key in document
    ]
    if len(identity_fields) != 1:
        fail()
    validate_string(document[identity_fields[0]], nonempty=True)
    profile = require_object(
        document["profile"],
        {"enabled"},
        V2_PROFILE_KEYS,
    )
    name_fields = [
        key for key in ("display_name", "name") if key in profile
    ]
    if len(name_fields) != 1:
        fail()
    validate_string(profile[name_fields[0]])
    validate_enabled(profile["enabled"])
    if "limits" in profile:
        limits = require_object(
            profile["limits"],
            {"quota"},
            {"quota"},
        )
        validate_quota(limits["quota"])
    if "contact" in profile:
        contact = require_object(
            profile["contact"],
            {"email"},
            {"email"},
        )
        validate_string(contact["email"])
    if "deprecated_code" in profile:
        validate_string(profile["deprecated_code"])
    if "tags" in document:
        validate_tags(document["tags"])
    if "deprecated" in document:
        deprecated = require_object(
            document["deprecated"],
            {"note"},
            {"note"},
        )
        validate_string(deprecated["note"])
    if "email" in document:
        validate_string(document["email"])
    if "quota" in document:
        validate_quota(document["quota"])
    return document


def migrate_document(source, policy):
    validate_v1(source)
    result = copy.deepcopy(source)
    result["schema_version"] = 2
    if policy in {"rename-fields", "combined-version-upgrade"}:
        result["id"] = result.pop("record_id")
        profile = result["profile"]
        profile["name"] = profile.pop("display_name")
    if policy in {"normalize-types", "combined-version-upgrade"}:
        profile = result["profile"]
        profile["enabled"] = normalize_enabled(profile["enabled"])
        if "limits" in profile:
            profile["limits"]["quota"] = normalize_quota(
                profile["limits"]["quota"]
            )
        if "tags" in result:
            tags = result["tags"]
            if type(tags) is str:
                result["tags"] = [tags]
            elif type(tags) is list:
                result["tags"] = list(tags)
            else:
                fail()
    if policy in {"lift-nested-members", "combined-version-upgrade"}:
        profile = result["profile"]
        contact = profile.pop("contact", None)
        if contact is not None:
            result["email"] = contact["email"]
        limits = profile.pop("limits", None)
        if limits is not None:
            result["quota"] = limits["quota"]
    if policy in {
        "drop-deprecated-members",
        "combined-version-upgrade",
    }:
        result.pop("deprecated", None)
        result["profile"].pop("deprecated_code", None)
    validate_v2(result)
    return result


def canonical_json(value):
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8", errors="strict")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError):
        fail()


def derive_outputs(parsed, shape, policy):
    documents = []
    entries = []
    for source_index, source_key, source in parsed:
        if source_index != len(documents):
            fail()
        relative = "documents/{:06d}.json".format(source_index)
        content = canonical_json(migrate_document(source, policy))
        if not content or len(content) > MAX_DOCUMENT_OUTPUT:
            fail()
        documents.append((relative, content))
        entries.append(
            {
                "file": relative,
                "source_index": source_index,
                "source_key": source_key,
            }
        )
    if not documents or len(documents) > MAX_DOCUMENTS:
        fail()
    manifest = canonical_json(
        {
            "input_shape": shape,
            "migration_policy": policy,
            "document_count": len(documents),
            "entries": entries,
        }
    )
    if not manifest or len(manifest) > MAX_MANIFEST_OUTPUT:
        fail()
    if len(manifest) + sum(len(item[1]) for item in documents) > MAX_TOTAL_OUTPUT:
        fail()
    return documents, manifest


def require_output_absent():
    try:
        os.lstat("output")
    except FileNotFoundError:
        return
    fail()


def write_exact(path, content):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o644)
    try:
        position = 0
        while position < len(content):
            written = os.write(descriptor, content[position:])
            if written <= 0:
                fail()
            position += written
        os.fchmod(descriptor, 0o644)
    finally:
        os.close(descriptor)


def publish(documents, manifest):
    require_output_absent()
    os.mkdir("output", 0o755)
    os.chmod("output", 0o755)
    os.mkdir("output/documents", 0o755)
    os.chmod("output/documents", 0o755)
    for relative, content in documents:
        write_exact("output/" + relative, content)
    write_exact("output/manifest.json", manifest)


def main():
    if len(sys.argv) != 3:
        fail()
    shape = sys.argv[1]
    policy = sys.argv[2]
    if shape not in SHAPES or policy not in POLICIES:
        fail()
    payload = read_source()
    parsed = parse_source(payload, shape)
    documents, manifest = derive_outputs(parsed, shape, policy)
    publish(documents, manifest)


try:
    main()
except Exception:
    raise SystemExit(66)
PYTHON
""".lstrip()


_HAND_AUTHORED_BASH_SHA256 = (
    "aeba83631e93aa7c22278f1150b5777e0517eb948f73ce6df33094ef1794d48b"
)
_HAND_AUTHORED_BASH_BYTE_COUNT = 16_045
_AGGREGATE_TEST_VECTOR_SHA256 = (
    "6e1d12e85f6cf904b392f21c64ab3cffb683b5be548198b283cffce65bf6c54d"
)
_BOUNDARY_VECTOR_SHA256 = (
    "7f90ebe7b491e3226545fa03ec19c6b04fc4d4a9f0a75d9b3bae0be2cecb4b11"
)
_FAILURE_VECTOR_SHA256 = (
    "f36cf44cb7ea7e33901c52726c91f5c30bba71170e201d691031ffcfd784e60e"
)


def _binary_paths() -> tuple[str, dict[str, str]]:
    if os.name != "posix":
        raise RuntimeError(
            "the fixed nested JSON migration Bash canary requires POSIX"
        )
    bash = shutil.which("bash")
    if bash is None or not os.access(bash, os.X_OK):
        raise RuntimeError("bash is unavailable or not executable")
    feature_probe = subprocess.run(
        [
            bash,
            "--noprofile",
            "--norc",
            "-c",
            "set -euo pipefail; value=ok; [[ $value == ok ]]",
        ],
        env={"LANG": "C", "LC_ALL": "C", "PATH": "", "TZ": "UTC"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=5,
    )
    if feature_probe.returncode != 0:
        raise RuntimeError("bash lacks the required strict-mode features")
    if migration.NESTED_JSON_SCHEMA_MIGRATION_ALLOWED_TOOLS != (
        "mkdir",
        "python3",
        "sort",
    ):
        raise RuntimeError(
            "family tool budget differs from the reviewed literal"
        )
    tools: dict[str, str] = {}
    for name in migration.NESTED_JSON_SCHEMA_MIGRATION_ALLOWED_TOOLS:
        path = shutil.which(name)
        if path is None or not os.access(path, os.X_OK):
            raise RuntimeError(
                f"required canary tool {name!r} is unavailable or not executable"
            )
        tools[name] = path
    python_probe = subprocess.run(
        [
            tools["python3"],
            "-I",
            "-S",
            "-c",
            (
                "import json,os,re,stat,sys,unicodedata; "
                "raise SystemExit(0 if json.dumps({'a': 1}, sort_keys=True)"
                " == '{\"a\": 1}' else 1)"
            ),
        ],
        env={"LANG": "C", "LC_ALL": "C", "PATH": "", "TZ": "UTC"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=5,
    )
    if (
        python_probe.returncode != 0
        or python_probe.stdout
        or python_probe.stderr
    ):
        raise RuntimeError(
            "python3 lacks the required isolated standard-library features"
        )
    return bash, tools


def _write_fixed_canary(
    root: Path,
    tools: dict[str, str],
) -> tuple[Path, Path]:
    tool_root = root / "allowed-tools"
    tool_root.mkdir(mode=0o700)
    for name, target in tools.items():
        os.symlink(Path(target).resolve(), tool_root / name)
    script = root / "fixed-nested-json-schema-migration-canary.bash"
    script.write_text(_HAND_AUTHORED_BASH, encoding="utf-8", newline="\n")
    script.chmod(0o400)
    return script, tool_root


def _run_fixed_canary(
    bash: str,
    script: Path,
    tool_root: Path,
    workspace: Path,
    input_shape: str,
    migration_policy: str,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            bash,
            "--noprofile",
            "--norc",
            str(script),
            input_shape,
            migration_policy,
        ],
        cwd=workspace,
        env={
            "HOME": str(workspace),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": str(tool_root),
            "TZ": "UTC",
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )


def _commit_piece(hasher: object, value: bytes) -> None:
    if type(value) is not bytes:
        raise TypeError("aggregate commitment pieces must be exact bytes")
    hasher.update(len(value).to_bytes(8, "big"))
    hasher.update(value)


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _base_v1_document(
    *,
    record_id: str = "key",
    display_name: str = "Boundary",
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "record_id": record_id,
        "profile": {
            "display_name": display_name,
            "enabled": "yes",
            "limits": {"quota": "7"},
            "contact": {"email": "mail@example.test"},
            "deprecated_code": "v1-only",
        },
        "tags": "tag",
        "deprecated": {"note": "retire"},
    }


def _manual_manifest(
    input_shape: str,
    migration_policy: str,
    count: int = 1,
    source_keys: tuple[str | None, ...] = (None,),
) -> bytes:
    return _canonical(
        {
            "input_shape": input_shape,
            "migration_policy": migration_policy,
            "document_count": count,
            "entries": [
                {
                    "file": f"documents/{index:06d}.json",
                    "source_index": index,
                    "source_key": source_keys[index],
                }
                for index in range(count)
            ],
        }
    )


def _materialize_manual_source(workspace: Path, payload: bytes) -> None:
    (workspace / "input").mkdir(parents=True)
    (workspace / migration.NESTED_JSON_SCHEMA_MIGRATION_INPUT).write_bytes(
        payload
    )


def _require_manual_output(
    workspace: Path,
    expected_manifest: bytes,
    expected_documents: tuple[bytes, ...],
) -> None:
    output = workspace / "output"
    documents = output / "documents"
    if stat.S_IMODE(output.stat().st_mode) != 0o755:
        raise RuntimeError("manual output directory has the wrong mode")
    if stat.S_IMODE(documents.stat().st_mode) != 0o755:
        raise RuntimeError("manual documents directory has the wrong mode")
    expected_paths = {
        Path("manifest.json"),
        Path("documents"),
        *(
            Path("documents") / f"{index:06d}.json"
            for index in range(len(expected_documents))
        ),
    }
    observed_paths = {
        path.relative_to(output)
        for path in output.rglob("*")
    }
    if observed_paths != expected_paths:
        raise RuntimeError("manual output tree differs from the closed tree")
    manifest_path = output / "manifest.json"
    if (
        stat.S_IMODE(manifest_path.stat().st_mode) != 0o644
        or manifest_path.read_bytes() != expected_manifest
    ):
        raise RuntimeError("manual manifest is not exact")
    for index, expected in enumerate(expected_documents):
        path = documents / f"{index:06d}.json"
        if (
            stat.S_IMODE(path.stat().st_mode) != 0o644
            or path.read_bytes() != expected
        ):
            raise RuntimeError("manual document output is not exact")


def _run_all_materializations() -> str:
    bash, tools = _binary_paths()
    tasks = migration.build_nested_json_schema_migration_tasks()
    if len(tasks) != 20 or len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES) != 5:
        raise RuntimeError("reviewed canary grid is not exactly 20 by 5")
    aggregate = sha256(
        b"cbds.fixed-nested-json-schema-migration-canary.v1\0"
    )
    passed = 0
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        script, tool_root = _write_fixed_canary(root, tools)
        if {item.name for item in tool_root.iterdir()} != set(
            migration.NESTED_JSON_SCHEMA_MIGRATION_ALLOWED_TOOLS
        ):
            raise RuntimeError(
                "restricted PATH does not exactly match tool budget"
            )
        for task_index, task in enumerate(tasks):
            if (
                task.candidate_execution_authorized is not False
                or task.model_selection_eligible is not False
                or task.claim_authorized is not False
            ):
                raise RuntimeError("task unexpectedly grants research authority")
            for profile_index, profile in enumerate(
                PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
            ):
                bundle = (
                    migration.build_nested_json_schema_migration_fixture_bundle(
                        task,
                        profile,
                    )
                )
                workspace = (
                    root
                    / "workspaces"
                    / f"{task_index:02d}-{profile_index}"
                )
                with migration.materialize_nested_json_schema_migration_fixture(
                    task,
                    profile,
                    bundle,
                    workspace,
                ) as handle:
                    completed = _run_fixed_canary(
                        bash,
                        script,
                        tool_root,
                        workspace,
                        task.parameters.input_shape,
                        task.parameters.migration_policy,
                    )
                    if (
                        completed.returncode != 0
                        or completed.stdout
                        or completed.stderr
                    ):
                        raise RuntimeError(
                            "reviewed Bash literal failed: "
                            + (completed.stdout + completed.stderr).decode(
                                "utf-8", errors="replace"
                            )
                        )
                    if not migration.verify_nested_json_schema_migration_workspace(
                        task,
                        profile,
                        bundle,
                        handle,
                    ):
                        raise RuntimeError(
                            "reviewed Bash literal failed trusted verification"
                        )
                    output_scan = handle.scan_outputs()
                    observed_manifest = handle.read_output_bytes(
                        output_scan,
                        migration.NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_MANIFEST,
                    )
                    if observed_manifest != bundle.oracle.state.manifest:
                        raise RuntimeError(
                            "reviewed Bash literal manifest is not byte-canonical"
                        )
                    observed_documents: list[tuple[str, bytes]] = []
                    for document in bundle.oracle.state.documents:
                        observed = handle.read_output_bytes(
                            output_scan,
                            f"output/{document.file}",
                        )
                        if observed != document.content:
                            raise RuntimeError(
                                "reviewed Bash literal document is not "
                                "byte-canonical"
                            )
                        observed_documents.append((document.file, observed))
                    for piece in (
                        task.task_id.encode("ascii"),
                        profile.profile_id.encode("ascii"),
                        bundle.definition.fixture_id.encode("ascii"),
                        bundle.definition.fixture_sha256.encode("ascii"),
                        bundle.fixture_definition_sha256.encode("ascii"),
                        bundle.descriptor.fixture_sha256.encode("ascii"),
                        migration.NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_MANIFEST.encode(
                            "ascii"
                        ),
                        observed_manifest,
                    ):
                        _commit_piece(aggregate, piece)
                    for relative, observed in observed_documents:
                        _commit_piece(aggregate, relative.encode("ascii"))
                        _commit_piece(aggregate, observed)
                    if (
                        bundle.candidate_execution_authorized is not False
                        or bundle.model_selection_eligible is not False
                        or bundle.claim_authorized is not False
                    ):
                        raise RuntimeError(
                            "fixture unexpectedly grants research authority"
                        )
                    passed += 1
    if passed != 100:
        raise RuntimeError("reviewed Bash literal did not cover 100 bundles")
    return aggregate.hexdigest()


def _boundary_vectors() -> tuple[
    bytes,
    bytes,
    bytes,
    bytes,
    bytes,
    bytes,
]:
    boundary_value = ("雪" * 42) + "ab"
    oversized_value = boundary_value + "b"
    if (
        len(boundary_value.encode("utf-8")) != 128
        or len(oversized_value.encode("utf-8")) != 129
    ):
        raise RuntimeError("UTF-8 boundary construction drifted")
    boundary_document = _base_v1_document(display_name=boundary_value)
    oversized_document = _base_v1_document(display_name=oversized_value)
    boundary_source = _canonical(boundary_document)
    oversized_source = _canonical(oversized_document)
    expected_boundary_document = _canonical(
        {
            "schema_version": 2,
            "id": "key",
            "profile": {
                "name": boundary_value,
                "enabled": True,
            },
            "tags": ["tag"],
            "email": "mail@example.test",
            "quota": 7,
        }
    )
    expected_boundary_manifest = _manual_manifest(
        "single-object",
        "combined-version-upgrade",
    )

    source_document = _base_v1_document(display_name="Source maximum")
    compact = _canonical(source_document)
    padding = (
        migration.NESTED_JSON_SCHEMA_MIGRATION_SOURCE_MAXIMUM_BYTES
        - len(compact)
    )
    if padding < 0:
        raise RuntimeError("boundary seed unexpectedly exceeds source bound")
    maximum_source = compact[:-1] + (b" " * padding) + b"\n"
    oversized_maximum_source = (
        compact[:-1] + (b" " * (padding + 1)) + b"\n"
    )
    if (
        len(maximum_source)
        != migration.NESTED_JSON_SCHEMA_MIGRATION_SOURCE_MAXIMUM_BYTES
        or len(oversized_maximum_source)
        != migration.NESTED_JSON_SCHEMA_MIGRATION_SOURCE_MAXIMUM_BYTES + 1
    ):
        raise RuntimeError("source byte boundary construction drifted")
    return (
        boundary_source,
        oversized_source,
        expected_boundary_manifest,
        expected_boundary_document,
        maximum_source,
        oversized_maximum_source,
    )


def _failure_cases() -> tuple[tuple[str, str, str, bytes], ...]:
    base = _base_v1_document()
    valid_line = _canonical(base)
    duplicate_key = (
        b'{"deprecated":{"note":"retire"},"profile":'
        b'{"display_name":"Boundary","enabled":true,"enabled":false},'
        b'"record_id":"key","schema_version":1}\n'
    )
    partial_after_valid = (
        valid_line
        + b'{"schema_version":1,"record_id":"tail","profile":'
        + b'{"display_name":"tail","enabled":true}\n'
    )
    wrong_enabled = _base_v1_document()
    wrong_enabled["profile"]["enabled"] = "TRUE"  # type: ignore[index]
    float_quota = _base_v1_document()
    float_quota["profile"]["limits"]["quota"] = 7.0  # type: ignore[index]
    negative_zero_quota = _base_v1_document()
    negative_zero_quota["profile"]["limits"]["quota"] = "-0"  # type: ignore[index]
    c1_control = _base_v1_document(display_name="bad\u0085value")
    format_control = _base_v1_document(display_name="bad\u200bvalue")
    map_mismatch = _canonical({"other": base})
    too_many = valid_line * 33
    cr_framed = valid_line[:-1] + b"\r\n"
    invalid_utf8 = valid_line[:-1] + b"\xff\n"
    return (
        (
            "duplicate-nested-member",
            "single-object",
            "rename-fields",
            duplicate_key,
        ),
        (
            "missing-final-lf",
            "single-object",
            "rename-fields",
            valid_line[:-1],
        ),
        (
            "valid-prefix-malformed-tail",
            "jsonl-objects",
            "combined-version-upgrade",
            partial_after_valid,
        ),
        (
            "closed-enabled-type",
            "single-object",
            "normalize-types",
            _canonical(wrong_enabled),
        ),
        (
            "floating-quota",
            "single-object",
            "normalize-types",
            _canonical(float_quota),
        ),
        (
            "negative-zero-quota",
            "single-object",
            "normalize-types",
            _canonical(negative_zero_quota),
        ),
        (
            "c1-control-string",
            "single-object",
            "rename-fields",
            _canonical(c1_control),
        ),
        (
            "format-control-string",
            "single-object",
            "rename-fields",
            _canonical(format_control),
        ),
        (
            "map-key-record-id-mismatch",
            "keyed-object-map",
            "rename-fields",
            map_mismatch,
        ),
        (
            "document-count-over-bound",
            "jsonl-objects",
            "drop-deprecated-members",
            too_many,
        ),
        (
            "jsonl-cr-framing",
            "jsonl-objects",
            "lift-nested-members",
            cr_framed,
        ),
        (
            "invalid-utf8",
            "single-object",
            "rename-fields",
            invalid_utf8,
        ),
    )


class NestedJsonSchemaMigrationBashCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = migration.build_nested_json_schema_migration_tasks()

    def test_fixed_literal_solves_all_twenty_cells_and_five_profiles(
        self,
    ) -> None:
        self.assertEqual(
            _run_all_materializations(),
            _AGGREGATE_TEST_VECTOR_SHA256,
        )

    def test_all_materializations_survive_opposite_optimization(self) -> None:
        _binary_paths()
        opposite = ("-O",) if sys.flags.optimize == 0 else ()
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.pathsep.join(
            (str(ROOT), str(ROOT / "src"))
        )
        script = (
            "from tests."
            "test_executable_nested_json_schema_migration_bash_canary "
            "import _AGGREGATE_TEST_VECTOR_SHA256, _run_all_materializations; "
            "observed = _run_all_materializations(); "
            "raise SystemExit("
            "0 if observed == _AGGREGATE_TEST_VECTOR_SHA256 else 1)"
        )
        completed = subprocess.run(
            [sys.executable, *opposite, "-c", script],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=360,
        )
        self.assertEqual(
            completed.returncode,
            0,
            completed.stdout + completed.stderr,
        )
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"")

    def test_utf8_and_source_byte_boundaries_are_exact(self) -> None:
        bash, tools = _binary_paths()
        (
            boundary_source,
            oversized_source,
            expected_boundary_manifest,
            expected_boundary_document,
            maximum_source,
            oversized_maximum_source,
        ) = _boundary_vectors()
        vector = sha256(
            b"cbds.nested-json-migration-boundary-vector.v1\0"
        )
        for piece in (
            boundary_source,
            oversized_source,
            expected_boundary_manifest,
            expected_boundary_document,
            maximum_source,
            oversized_maximum_source,
        ):
            _commit_piece(vector, piece)
        self.assertEqual(vector.hexdigest(), _BOUNDARY_VECTOR_SHA256)

        expected_maximum_document = _canonical(
            {
                "schema_version": 2,
                "id": "key",
                "profile": {
                    "name": "Source maximum",
                    "enabled": "yes",
                    "limits": {"quota": "7"},
                    "contact": {"email": "mail@example.test"},
                    "deprecated_code": "v1-only",
                },
                "tags": "tag",
                "deprecated": {"note": "retire"},
            }
        )
        expected_maximum_manifest = _manual_manifest(
            "single-object",
            "rename-fields",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, tool_root = _write_fixed_canary(root, tools)

            boundary_workspace = root / "boundary-valid"
            _materialize_manual_source(boundary_workspace, boundary_source)
            boundary = _run_fixed_canary(
                bash,
                script,
                tool_root,
                boundary_workspace,
                "single-object",
                "combined-version-upgrade",
            )
            self.assertEqual(
                boundary.returncode,
                0,
                boundary.stdout + boundary.stderr,
            )
            self.assertEqual(boundary.stdout, b"")
            self.assertEqual(boundary.stderr, b"")
            _require_manual_output(
                boundary_workspace,
                expected_boundary_manifest,
                (expected_boundary_document,),
            )

            maximum_workspace = root / "source-maximum-valid"
            _materialize_manual_source(maximum_workspace, maximum_source)
            maximum = _run_fixed_canary(
                bash,
                script,
                tool_root,
                maximum_workspace,
                "single-object",
                "rename-fields",
            )
            self.assertEqual(
                maximum.returncode,
                0,
                maximum.stdout + maximum.stderr,
            )
            self.assertEqual(maximum.stdout, b"")
            self.assertEqual(maximum.stderr, b"")
            _require_manual_output(
                maximum_workspace,
                expected_maximum_manifest,
                (expected_maximum_document,),
            )

            for name, source in (
                ("scalar-oversized", oversized_source),
                ("source-oversized", oversized_maximum_source),
            ):
                workspace = root / name
                _materialize_manual_source(workspace, source)
                completed = _run_fixed_canary(
                    bash,
                    script,
                    tool_root,
                    workspace,
                    "single-object",
                    "combined-version-upgrade",
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(completed.stdout, b"")
                self.assertEqual(completed.stderr, b"")
                self.assertFalse((workspace / "output").exists())

    def test_malformed_type_framing_and_partial_input_fail_closed(
        self,
    ) -> None:
        cases = _failure_cases()
        vector = sha256(
            b"cbds.nested-json-migration-failure-vector.v1\0"
        )
        for name, shape, policy, payload in cases:
            for piece in (
                name.encode("ascii"),
                shape.encode("ascii"),
                policy.encode("ascii"),
                payload,
            ):
                _commit_piece(vector, piece)
        self.assertEqual(vector.hexdigest(), _FAILURE_VECTOR_SHA256)

        bash, tools = _binary_paths()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, tool_root = _write_fixed_canary(root, tools)
            for index, (name, shape, policy, payload) in enumerate(cases):
                workspace = root / f"failure-{index:02d}-{name}"
                _materialize_manual_source(workspace, payload)
                before = (
                    workspace
                    / migration.NESTED_JSON_SCHEMA_MIGRATION_INPUT
                ).read_bytes()
                completed = _run_fixed_canary(
                    bash,
                    script,
                    tool_root,
                    workspace,
                    shape,
                    policy,
                )
                self.assertNotEqual(completed.returncode, 0, name)
                self.assertEqual(completed.stdout, b"", name)
                self.assertEqual(completed.stderr, b"", name)
                self.assertFalse((workspace / "output").exists(), name)
                self.assertEqual(
                    (
                        workspace
                        / migration.NESTED_JSON_SCHEMA_MIGRATION_INPUT
                    ).read_bytes(),
                    before,
                    name,
                )

    def test_literal_hash_tool_budget_vectors_and_nonclaim_boundary(
        self,
    ) -> None:
        self.assertEqual(
            migration.NESTED_JSON_SCHEMA_MIGRATION_ALLOWED_TOOLS,
            ("mkdir", "python3", "sort"),
        )
        self.assertEqual(
            migration.NESTED_JSON_SCHEMA_MIGRATION_INPUT_SHAPES,
            (
                "single-object",
                "object-array",
                "keyed-object-map",
                "jsonl-objects",
            ),
        )
        self.assertEqual(
            migration.NESTED_JSON_SCHEMA_MIGRATION_POLICIES,
            (
                "rename-fields",
                "normalize-types",
                "lift-nested-members",
                "drop-deprecated-members",
                "combined-version-upgrade",
            ),
        )
        self.assertEqual(
            migration.NESTED_JSON_SCHEMA_MIGRATION_INPUT,
            "input/documents.data",
        )
        self.assertEqual(
            migration.NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_MANIFEST,
            "output/manifest.json",
        )
        self.assertEqual(
            migration.NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_DIRECTORY,
            "output/documents",
        )
        self.assertEqual(
            migration.NESTED_JSON_SCHEMA_MIGRATION_OUTPUT_MODE,
            0o644,
        )
        self.assertEqual(
            migration.NESTED_JSON_SCHEMA_MIGRATION_SOURCE_MAXIMUM_BYTES,
            128 * 1024,
        )
        self.assertEqual(
            migration.NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DOCUMENTS,
            32,
        )
        self.assertEqual(
            migration.NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_DEPTH,
            8,
        )
        self.assertEqual(
            migration.NESTED_JSON_SCHEMA_MIGRATION_MAXIMUM_NODES,
            4096,
        )
        self.assertEqual(
            migration.NESTED_JSON_SCHEMA_MIGRATION_SCALAR_MAXIMUM_UTF8_BYTES,
            128,
        )
        self.assertEqual(len(self.tasks), 20)
        self.assertEqual(len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES), 5)
        self.assertTrue(
            all(
                task.candidate_execution_authorized is False
                and task.model_selection_eligible is False
                and task.claim_authorized is False
                for task in self.tasks
            )
        )
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
            self.assertIs(profile.candidate_execution_authorized, False)
            self.assertIs(profile.model_selection_eligible, False)
            self.assertIs(profile.claim_authorized, False)

        self.assertIs(
            migration.NESTED_JSON_SCHEMA_MIGRATION_FINAL_OUTPUT_OBSERVED,
            True,
        )
        self.assertIs(
            migration.NESTED_JSON_SCHEMA_MIGRATION_INPUT_PRESERVATION_OBSERVED,
            True,
        )
        self.assertIs(
            migration.NESTED_JSON_SCHEMA_MIGRATION_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE,
            True,
        )
        for boundary in (
            migration.NESTED_JSON_SCHEMA_MIGRATION_ATOMICITY_OBSERVED,
            migration.NESTED_JSON_SCHEMA_MIGRATION_TOOL_HISTORY_OBSERVED,
            migration.NESTED_JSON_SCHEMA_MIGRATION_READ_SCOPE_OBSERVED,
            migration.NESTED_JSON_SCHEMA_MIGRATION_CANDIDATE_EXIT_STATUS_OBSERVED,
            migration.NESTED_JSON_SCHEMA_MIGRATION_TRANSIENT_STATE_OBSERVED,
            migration.NESTED_JSON_SCHEMA_MIGRATION_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
        ):
            self.assertIs(boundary, False)

        self.assertNotIn("/usr/bin/", _HAND_AUTHORED_BASH)
        self.assertNotIn("/bin/", _HAND_AUTHORED_BASH)
        self.assertNotIn("subprocess", _HAND_AUTHORED_BASH)
        self.assertNotIn("socket", _HAND_AUTHORED_BASH)
        self.assertNotIn("eval ", _HAND_AUTHORED_BASH)
        self.assertNotIn("exec(", _HAND_AUTHORED_BASH)
        self.assertIn(
            'input_shape=${1:?input shape required}',
            _HAND_AUTHORED_BASH,
        )
        self.assertIn(
            'migration_policy=${2:?migration policy required}',
            _HAND_AUTHORED_BASH,
        )
        self.assertIn(
            'python3 -I -S - "$input_shape" "$migration_policy"',
            _HAND_AUTHORED_BASH,
        )
        self.assertIn('INPUT = "input/documents.data"', _HAND_AUTHORED_BASH)
        self.assertIn('os.mkdir("output", 0o755)', _HAND_AUTHORED_BASH)
        self.assertIn(
            'os.mkdir("output/documents", 0o755)',
            _HAND_AUTHORED_BASH,
        )
        self.assertEqual(
            sha256(_HAND_AUTHORED_BASH.encode("utf-8")).hexdigest(),
            _HAND_AUTHORED_BASH_SHA256,
        )
        self.assertEqual(
            len(_HAND_AUTHORED_BASH.encode("utf-8")),
            _HAND_AUTHORED_BASH_BYTE_COUNT,
        )
        self.assertRegex(_AGGREGATE_TEST_VECTOR_SHA256, r"\A[0-9a-f]{64}\Z")
        self.assertRegex(_BOUNDARY_VECTOR_SHA256, r"\A[0-9a-f]{64}\Z")
        self.assertRegex(_FAILURE_VECTOR_SHA256, r"\A[0-9a-f]{64}\Z")


if __name__ == "__main__":
    unittest.main()
