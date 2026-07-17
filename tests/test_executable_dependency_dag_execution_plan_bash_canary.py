"""Fixed reviewed Bash feasibility canary for dependency execution plans.

Only the immutable Bash literal below is executed.  It is public
method-development feasibility evidence for one source-reviewed program, not
a caller-selected candidate API, production sandbox, scored evaluation,
model-selection input, or evidence about model quality.  Its restricted PATH
demonstrates only that this literal stays within the family's exact external
tool budget.  Python's isolated mode and the PATH do not confine Python
modules, syscalls, or reads.  Final-state verification does not prove tool
history, read scope, filesystem atomicity, transient behavior, candidate exit
status, or global quiescence.
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

import cbds.executable_dependency_dag_execution_plan as dag  # noqa: E402
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

if [[ $# -ne 2 ]]; then
    exit 63
fi
graph_encoding=$1
tie_break_policy=$2
case $graph_encoding in
    json-adjacency|json-edge-list|csv-edges|line-oriented-dependencies) ;;
    *) exit 64 ;;
esac
case $tie_break_policy in
    utf8-smallest|declared-priority|shortest-depth|largest-fanout|stable-input-order) ;;
    *) exit 65 ;;
esac

python3 -I -S - "$graph_encoding" "$tie_break_policy" <<'PYTHON'
import csv
import io
import json
import os
import re
import stat
import sys
import unicodedata


INPUT = "input/graph.data"
OUTPUT = "output/execution-plan.json"
MAX_SOURCE = 128 * 1024
MAX_NODES = 64
MAX_PHYSICAL_DEPENDENCIES = 512
MAX_UNIQUE_EDGES = 256
MAX_JSON_DEPTH = 8
MAX_JSON_NODES = 4096
MAX_IDENTIFIER_BYTES = 128
MAX_PRIORITY = 1000000
MAX_OUTPUT = 64 * 1024
ENCODINGS = (
    "json-adjacency",
    "json-edge-list",
    "csv-edges",
    "line-oriented-dependencies",
)
POLICIES = (
    "utf8-smallest",
    "declared-priority",
    "shortest-depth",
    "largest-fanout",
    "stable-input-order",
)
CANONICAL_DECIMAL = re.compile(r"(?:0|-?[1-9][0-9]{0,6})\Z")


class InvalidGraph(Exception):
    pass


def fail():
    raise InvalidGraph()


def validate_identifier(value):
    if type(value) is not str or not value:
        fail()
    if any(
        unicodedata.category(character) in {"Cc", "Cf"}
        for character in value
    ):
        fail()
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        fail()
    if len(encoded) > MAX_IDENTIFIER_BYTES:
        fail()
    return value


def bounded_text_integer(token):
    if type(token) is not str or CANONICAL_DECIMAL.fullmatch(token) is None:
        fail()
    value = int(token)
    if abs(value) > MAX_PRIORITY:
        fail()
    return value


def bounded_json_integer(token):
    return bounded_text_integer(token)


def reject_float(_token):
    fail()


def reject_constant(_token):
    fail()


def reject_duplicate_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail()
        result[key] = value
    return result


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
            if depth > MAX_JSON_DEPTH:
                fail()
        elif character in "]}":
            depth -= 1
            if depth < 0:
                fail()
    if in_string or escaped or depth != 0:
        fail()


def validate_json_tree(root):
    stack = [(root, 1)]
    count = 0
    while stack:
        value, depth = stack.pop()
        count += 1
        if count > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            fail()
        if type(value) is dict:
            for key, item in value.items():
                if type(key) is not str:
                    fail()
                stack.append((item, depth + 1))
        elif type(value) is list:
            for item in value:
                stack.append((item, depth + 1))
        elif type(value) is str:
            try:
                value.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                fail()
        elif value is None or type(value) in {bool, int}:
            pass
        else:
            fail()


def decode_json(payload):
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
            parse_int=bounded_json_integer,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
    except InvalidGraph:
        raise
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        fail()
    validate_json_tree(value)
    return value


def require_exact_object(value, keys):
    if type(value) is not dict or set(value) != keys:
        fail()
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
    if not payload or len(payload) > MAX_SOURCE:
        fail()
    return payload


def new_graph():
    return [], {}, [], 0


def add_node(nodes, priorities, identifier, priority):
    identifier = validate_identifier(identifier)
    if type(priority) is not int or type(priority) is bool:
        fail()
    if abs(priority) > MAX_PRIORITY or identifier in priorities:
        fail()
    if len(nodes) >= MAX_NODES:
        fail()
    nodes.append(identifier)
    priorities[identifier] = priority


def add_dependency(references, physical_count, dependent, prerequisite):
    dependent = validate_identifier(dependent)
    prerequisite = validate_identifier(prerequisite)
    physical_count += 1
    if physical_count > MAX_PHYSICAL_DEPENDENCIES:
        fail()
    references.append((prerequisite, dependent))
    return physical_count


def parse_json_adjacency(payload):
    if (
        not payload.endswith(b"\n")
        or payload.endswith(b"\r\n")
        or payload.endswith(b"\n\n")
    ):
        fail()
    root = require_exact_object(decode_json(payload[:-1]), {"nodes"})
    raw_nodes = root["nodes"]
    if type(raw_nodes) is not list or not raw_nodes:
        fail()
    nodes, priorities, references, physical = new_graph()
    for raw in raw_nodes:
        item = require_exact_object(
            raw,
            {"id", "priority", "depends_on"},
        )
        add_node(nodes, priorities, item["id"], item["priority"])
        dependencies = item["depends_on"]
        if type(dependencies) is not list:
            fail()
        for prerequisite in dependencies:
            physical = add_dependency(
                references,
                physical,
                item["id"],
                prerequisite,
            )
    return nodes, priorities, references


def parse_json_edge_list(payload):
    if (
        not payload.endswith(b"\n")
        or payload.endswith(b"\r\n")
        or payload.endswith(b"\n\n")
    ):
        fail()
    root = require_exact_object(
        decode_json(payload[:-1]),
        {"nodes", "edges"},
    )
    raw_nodes = root["nodes"]
    raw_edges = root["edges"]
    if type(raw_nodes) is not list or not raw_nodes:
        fail()
    if type(raw_edges) is not list:
        fail()
    nodes, priorities, references, physical = new_graph()
    for raw in raw_nodes:
        item = require_exact_object(raw, {"id", "priority"})
        add_node(nodes, priorities, item["id"], item["priority"])
    for raw in raw_edges:
        item = require_exact_object(
            raw,
            {"dependent", "prerequisite"},
        )
        physical = add_dependency(
            references,
            physical,
            item["dependent"],
            item["prerequisite"],
        )
    return nodes, priorities, references


def require_crlf_framing(payload):
    if not payload.endswith(b"\r\n"):
        fail()
    for index, value in enumerate(payload):
        if value == 10 and (index == 0 or payload[index - 1] != 13):
            fail()
        if value == 13 and (
            index + 1 >= len(payload) or payload[index + 1] != 10
        ):
            fail()


def validate_rfc4180_lexical(text):
    index = 0
    in_quotes = False
    after_quote = False
    at_field_start = True
    while index < len(text):
        character = text[index]
        if in_quotes:
            if character == '"':
                if index + 1 < len(text) and text[index + 1] == '"':
                    index += 2
                    continue
                in_quotes = False
                after_quote = True
            index += 1
            continue
        if after_quote:
            if character == ",":
                after_quote = False
                at_field_start = True
                index += 1
                continue
            if text.startswith("\r\n", index):
                after_quote = False
                at_field_start = True
                index += 2
                continue
            fail()
        if character == '"':
            if not at_field_start:
                fail()
            in_quotes = True
            at_field_start = False
            index += 1
            continue
        if character == ",":
            at_field_start = True
            index += 1
            continue
        if text.startswith("\r\n", index):
            at_field_start = True
            index += 2
            continue
        if character in {"\r", "\n"}:
            fail()
        at_field_start = False
        index += 1
    if in_quotes or after_quote or not at_field_start:
        fail()


def parse_csv_edges(payload):
    require_crlf_framing(payload)
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        fail()
    if text.startswith("\ufeff"):
        fail()
    validate_rfc4180_lexical(text)
    try:
        reader = csv.reader(
            io.StringIO(text, newline=""),
            dialect="excel",
            strict=True,
        )
        rows = list(reader)
    except (csv.Error, UnicodeError):
        fail()
    if not rows or rows[0] != [
        "record",
        "node",
        "priority",
        "dependency",
    ]:
        fail()
    nodes, priorities, references, physical = new_graph()
    for row in rows[1:]:
        if len(row) != 4:
            fail()
        record, node, priority, dependency = row
        if record == "node":
            if dependency != "":
                fail()
            add_node(
                nodes,
                priorities,
                node,
                bounded_text_integer(priority),
            )
        elif record == "edge":
            if priority != "":
                fail()
            physical = add_dependency(
                references,
                physical,
                node,
                dependency,
            )
        else:
            fail()
    if not nodes:
        fail()
    return nodes, priorities, references


def parse_line_dependencies(payload):
    if not payload.endswith(b"\n") or b"\r" in payload:
        fail()
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        fail()
    if text.startswith("\ufeff"):
        fail()
    lines = text[:-1].split("\n")
    if not lines or any(line == "" for line in lines):
        fail()
    nodes, priorities, references, physical = new_graph()
    for line in lines:
        fields = line.split("\t")
        if len(fields) < 2:
            fail()
        priority = bounded_text_integer(fields[0])
        node = fields[1]
        add_node(nodes, priorities, node, priority)
        for prerequisite in fields[2:]:
            physical = add_dependency(
                references,
                physical,
                node,
                prerequisite,
            )
    return nodes, priorities, references


def parse_source(payload, encoding):
    if encoding == "json-adjacency":
        return parse_json_adjacency(payload)
    if encoding == "json-edge-list":
        return parse_json_edge_list(payload)
    if encoding == "csv-edges":
        return parse_csv_edges(payload)
    if encoding == "line-oriented-dependencies":
        return parse_line_dependencies(payload)
    fail()


def utf8_key(value):
    return value.encode("utf-8", errors="strict")


def normalize_graph(nodes, priorities, references):
    declared = set(nodes)
    if len(nodes) != len(declared) or not nodes:
        fail()
    edges = set()
    for prerequisite, dependent in references:
        if prerequisite not in declared or dependent not in declared:
            fail()
        edges.add((prerequisite, dependent))
    if len(edges) > MAX_UNIQUE_EDGES:
        fail()
    outgoing = {node: set() for node in nodes}
    indegree = {node: 0 for node in nodes}
    for prerequisite, dependent in edges:
        outgoing[prerequisite].add(dependent)
        indegree[dependent] += 1
    return edges, outgoing, indegree


def kahn_residual(nodes, outgoing, indegree):
    remaining = set(nodes)
    work = dict(indegree)
    ready = {node for node in nodes if work[node] == 0}
    while ready:
        node = min(ready, key=utf8_key)
        ready.remove(node)
        remaining.remove(node)
        for dependent in outgoing[node]:
            work[dependent] -= 1
            if work[dependent] == 0:
                ready.add(dependent)
    return remaining


def lies_on_cycle(start, outgoing):
    pending = list(outgoing[start])
    seen = set()
    while pending:
        node = pending.pop()
        if node == start:
            return True
        if node in seen:
            continue
        seen.add(node)
        pending.extend(outgoing[node])
    return False


def compute_depths(nodes, outgoing, indegree):
    work = dict(indegree)
    depths = {node: 0 for node in nodes}
    ready = {node for node in nodes if work[node] == 0}
    visited = 0
    while ready:
        node = min(ready, key=utf8_key)
        ready.remove(node)
        visited += 1
        for dependent in outgoing[node]:
            depths[dependent] = max(
                depths[dependent],
                depths[node] + 1,
            )
            work[dependent] -= 1
            if work[dependent] == 0:
                ready.add(dependent)
    if visited != len(nodes):
        fail()
    return depths


def derive_plan(nodes, priorities, outgoing, indegree, policy):
    depths = compute_depths(nodes, outgoing, indegree)
    declared_index = {
        node: index
        for index, node in enumerate(nodes)
    }

    def policy_key(node):
        encoded = utf8_key(node)
        if policy == "utf8-smallest":
            return (encoded,)
        if policy == "declared-priority":
            return (-priorities[node], encoded)
        if policy == "shortest-depth":
            return (depths[node], encoded)
        if policy == "largest-fanout":
            return (-len(outgoing[node]), encoded)
        if policy == "stable-input-order":
            return (declared_index[node], encoded)
        fail()

    work = dict(indegree)
    ready = {node for node in nodes if work[node] == 0}
    plan = []
    while ready:
        node = min(ready, key=policy_key)
        ready.remove(node)
        plan.append(node)
        for dependent in outgoing[node]:
            work[dependent] -= 1
            if work[dependent] == 0:
                ready.add(dependent)
    if len(plan) != len(nodes):
        fail()
    return plan


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


def derive_output(nodes, priorities, references, encoding, policy):
    edges, outgoing, indegree = normalize_graph(
        nodes,
        priorities,
        references,
    )
    residual = kahn_residual(nodes, outgoing, indegree)
    if residual:
        status = "cycle"
        plan = []
        blocked = sorted(residual, key=utf8_key)
        cyclic = sorted(
            (
                node
                for node in residual
                if lies_on_cycle(node, outgoing)
            ),
            key=utf8_key,
        )
        if not cyclic:
            fail()
    else:
        status = "valid"
        plan = derive_plan(nodes, priorities, outgoing, indegree, policy)
        blocked = []
        cyclic = []
    output = canonical_json(
        {
            "graph_encoding": encoding,
            "tie_break_policy": policy,
            "status": status,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "plan": plan,
            "blocked_nodes": blocked,
            "cyclic_nodes": cyclic,
        }
    )
    if not output or len(output) > MAX_OUTPUT:
        fail()
    return output


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


def publish(content):
    require_output_absent()
    os.mkdir("output", 0o755)
    os.chmod("output", 0o755)
    write_exact(OUTPUT, content)


def main():
    if len(sys.argv) != 3:
        fail()
    encoding = sys.argv[1]
    policy = sys.argv[2]
    if encoding not in ENCODINGS or policy not in POLICIES:
        fail()
    payload = read_source()
    nodes, priorities, references = parse_source(payload, encoding)
    output = derive_output(
        nodes,
        priorities,
        references,
        encoding,
        policy,
    )
    publish(output)


try:
    main()
except Exception:
    raise SystemExit(66)
PYTHON
""".lstrip()


_HAND_AUTHORED_BASH_SHA256 = (
    "28da7b6dba511c534accc63c71c0aa882c69f5f123cb8cdaf641bb0f39681de3"
)
_HAND_AUTHORED_BASH_BYTE_COUNT = 18_528
_AGGREGATE_TEST_VECTOR_SHA256 = (
    "4a046f4f7f1dd74911b99ea302ff59ce32eefed939c7c94184fcdb893c6b3d0e"
)
_BOUNDARY_VECTOR_SHA256 = (
    "3cd482a20e4e108dcac0888207edebfaa135725d23168bbda30902f3fea19c32"
)
_FAILURE_VECTOR_SHA256 = (
    "5ee40cf596e7bb71fed18b1ed14f6dd1a191e26735f75c3309436445f1518635"
)


def _binary_paths() -> tuple[str, dict[str, str]]:
    if os.name != "posix":
        raise RuntimeError(
            "the fixed dependency DAG Bash canary requires POSIX"
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
    if dag.DEPENDENCY_DAG_EXECUTION_PLAN_ALLOWED_TOOLS != (
        "mkdir",
        "python3",
    ):
        raise RuntimeError(
            "family tool budget differs from the reviewed literal"
        )
    tools: dict[str, str] = {}
    for name in dag.DEPENDENCY_DAG_EXECUTION_PLAN_ALLOWED_TOOLS:
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
                "import csv,io,json,os,re,stat,sys,unicodedata; "
                "raise SystemExit(0 if "
                "json.dumps({'a': 1}, sort_keys=True) == '{\"a\": 1}' "
                "else 1)"
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
    script = root / "fixed-dependency-dag-execution-plan-canary.bash"
    script.write_text(_HAND_AUTHORED_BASH, encoding="utf-8", newline="\n")
    script.chmod(0o400)
    return script, tool_root


def _run_fixed_canary(
    bash: str,
    script: Path,
    tool_root: Path,
    workspace: Path,
    graph_encoding: str,
    tie_break_policy: str,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            bash,
            "--noprofile",
            "--norc",
            str(script),
            graph_encoding,
            tie_break_policy,
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


def _expected_output(
    graph_encoding: str,
    tie_break_policy: str,
    *,
    status: str,
    node_count: int,
    edge_count: int,
    plan: list[str],
    blocked_nodes: list[str] | None = None,
    cyclic_nodes: list[str] | None = None,
) -> bytes:
    return _canonical(
        {
            "graph_encoding": graph_encoding,
            "tie_break_policy": tie_break_policy,
            "status": status,
            "node_count": node_count,
            "edge_count": edge_count,
            "plan": plan,
            "blocked_nodes": (
                [] if blocked_nodes is None else blocked_nodes
            ),
            "cyclic_nodes": (
                [] if cyclic_nodes is None else cyclic_nodes
            ),
        }
    )


def _json_adjacency(
    nodes: list[tuple[str, int, list[str]]],
) -> bytes:
    return _canonical(
        {
            "nodes": [
                {
                    "id": identifier,
                    "priority": priority,
                    "depends_on": dependencies,
                }
                for identifier, priority, dependencies in nodes
            ]
        }
    )


def _line_graph(
    nodes: list[tuple[int, str, list[str]]],
) -> bytes:
    return (
        "\n".join(
            "\t".join(
                (str(priority), identifier, *dependencies)
            )
            for priority, identifier, dependencies in nodes
        )
        + "\n"
    ).encode("utf-8")


def _materialize_manual_source(workspace: Path, payload: bytes) -> None:
    (workspace / "input").mkdir(parents=True)
    (workspace / dag.DEPENDENCY_DAG_EXECUTION_PLAN_INPUT).write_bytes(
        payload
    )


def _require_manual_output(
    workspace: Path,
    expected: bytes,
) -> None:
    output = workspace / "output"
    output_file = workspace / dag.DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT
    if stat.S_IMODE(output.stat().st_mode) != 0o755:
        raise RuntimeError("manual output directory has the wrong mode")
    observed_paths = {
        path.relative_to(output)
        for path in output.rglob("*")
    }
    if observed_paths != {Path("execution-plan.json")}:
        raise RuntimeError("manual output tree differs from the closed tree")
    if (
        stat.S_IMODE(output_file.stat().st_mode) != 0o644
        or output_file.read_bytes() != expected
    ):
        raise RuntimeError("manual execution plan is not exact")


def _run_all_materializations() -> str:
    bash, tools = _binary_paths()
    tasks = dag.build_dependency_dag_execution_plan_tasks()
    if len(tasks) != 20 or len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES) != 5:
        raise RuntimeError("reviewed canary grid is not exactly 20 by 5")
    aggregate = sha256(
        b"cbds.fixed-dependency-dag-execution-plan-canary.v1\0"
    )
    passed = 0
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        script, tool_root = _write_fixed_canary(root, tools)
        if {item.name for item in tool_root.iterdir()} != set(
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_ALLOWED_TOOLS
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
                bundle = dag.build_dependency_dag_execution_plan_fixture_bundle(
                    task,
                    profile,
                )
                workspace = (
                    root
                    / "workspaces"
                    / f"{task_index:02d}-{profile_index}"
                )
                with dag.materialize_dependency_dag_execution_plan_fixture(
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
                        task.parameters.graph_encoding,
                        task.parameters.tie_break_policy,
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
                    if not dag.verify_dependency_dag_execution_plan_workspace(
                        task,
                        profile,
                        bundle,
                        handle,
                    ):
                        raise RuntimeError(
                            "reviewed Bash literal failed trusted verification"
                        )
                    output_scan = handle.scan_outputs()
                    observed = handle.read_output_bytes(
                        output_scan,
                        dag.DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT,
                    )
                    if observed != bundle.oracle.state.content:
                        raise RuntimeError(
                            "reviewed Bash literal is not byte-canonical"
                        )
                    for piece in (
                        task.task_id.encode("ascii"),
                        profile.profile_id.encode("ascii"),
                        bundle.definition.fixture_id.encode("ascii"),
                        bundle.definition.fixture_sha256.encode("ascii"),
                        bundle.fixture_definition_sha256.encode("ascii"),
                        bundle.descriptor.fixture_sha256.encode("ascii"),
                        observed,
                    ):
                        _commit_piece(aggregate, piece)
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


def _dense_edge_source(edge_count: int) -> bytes:
    identifiers = [f"n{index:02d}" for index in range(64)]
    dependencies = {identifier: [] for identifier in identifiers}
    remaining = edge_count
    for dependent_index in range(1, len(identifiers)):
        for prerequisite_index in range(dependent_index):
            if remaining == 0:
                break
            dependencies[identifiers[dependent_index]].append(
                identifiers[prerequisite_index]
            )
            remaining -= 1
        if remaining == 0:
            break
    if remaining:
        raise RuntimeError("dense edge boundary construction drifted")
    return _line_graph(
        [
            (0, identifier, dependencies[identifier])
            for identifier in identifiers
        ]
    )


def _boundary_vectors() -> tuple[
    bytes,
    bytes,
    bytes,
    bytes,
    bytes,
    bytes,
    bytes,
    bytes,
    bytes,
]:
    boundary_id = ("雪" * 42) + "ab"
    oversized_id = boundary_id + "b"
    if (
        len(boundary_id.encode("utf-8")) != 128
        or len(oversized_id.encode("utf-8")) != 129
    ):
        raise RuntimeError("UTF-8 boundary construction drifted")
    boundary_source = _json_adjacency(
        [(boundary_id, 1_000_000, [])]
    )
    oversized_source = _json_adjacency(
        [(oversized_id, 1_000_000, [])]
    )
    expected_boundary = _expected_output(
        "json-adjacency",
        "declared-priority",
        status="valid",
        node_count=1,
        edge_count=0,
        plan=[boundary_id],
    )

    maximum_seed = _json_adjacency(
        [("maximum-source", -1_000_000, [])]
    )
    padding = (
        dag.DEPENDENCY_DAG_EXECUTION_PLAN_SOURCE_MAXIMUM_BYTES
        - len(maximum_seed)
    )
    if padding < 0:
        raise RuntimeError("source boundary seed exceeds its bound")
    maximum_source = maximum_seed[:-1] + (b" " * padding) + b"\n"
    oversized_maximum_source = (
        maximum_seed[:-1] + (b" " * (padding + 1)) + b"\n"
    )
    if (
        len(maximum_source)
        != dag.DEPENDENCY_DAG_EXECUTION_PLAN_SOURCE_MAXIMUM_BYTES
        or len(oversized_maximum_source)
        != dag.DEPENDENCY_DAG_EXECUTION_PLAN_SOURCE_MAXIMUM_BYTES + 1
    ):
        raise RuntimeError("source byte boundary construction drifted")

    repeated_512 = _line_graph(
        [
            (0, "root", []),
            (0, "dependent", ["root"] * 512),
        ]
    )
    repeated_513 = _line_graph(
        [
            (0, "root", []),
            (0, "dependent", ["root"] * 513),
        ]
    )
    unique_256 = _dense_edge_source(256)
    unique_257 = _dense_edge_source(257)
    return (
        boundary_source,
        oversized_source,
        expected_boundary,
        maximum_source,
        oversized_maximum_source,
        repeated_512,
        repeated_513,
        unique_256,
        unique_257,
    )


def _failure_cases() -> tuple[tuple[str, str, str, bytes], ...]:
    duplicate_root_key = (
        b'{"nodes":[{"id":"a","priority":0,"depends_on":[]}],'
        b'"nodes":[]}\n'
    )
    float_priority = (
        b'{"nodes":[{"id":"a","priority":1.0,"depends_on":[]}]}\n'
    )
    bool_priority = (
        b'{"nodes":[{"id":"a","priority":true,"depends_on":[]}]}\n'
    )
    negative_zero = (
        b'{"nodes":[{"id":"a","priority":-0,"depends_on":[]}]}\n'
    )
    lone_surrogate = (
        b'{"nodes":[{"id":"\\ud800","priority":0,"depends_on":[]}]}\n'
    )
    duplicate_node = _json_adjacency(
        [("same", 0, []), ("same", 1, [])]
    )
    unknown_dependency = _json_adjacency(
        [("known", 0, ["missing"])]
    )
    csv_header = b"kind,node,priority,dependency\r\n"
    csv_lf = (
        b"record,node,priority,dependency\n"
        b"node,a,0,\n"
    )
    csv_bad_quote = (
        b"record,node,priority,dependency\r\n"
        b'node,"unterminated,0,\r\n'
    )
    csv_unquoted_quote = (
        b"record,node,priority,dependency\r\n"
        b'node,a"b,0,\r\n'
    )
    csv_after_quote = (
        b"record,node,priority,dependency\r\n"
        b'node,"a"x,0,\r\n'
    )
    csv_duplicate = (
        b"record,node,priority,dependency\r\n"
        b"node,a,0,\r\n"
        b"node,a,1,\r\n"
    )
    csv_unknown = (
        b"record,node,priority,dependency\r\n"
        b"edge,a,,missing\r\n"
        b"node,a,0,\r\n"
    )
    line_duplicate = b"0\ta\n1\ta\n"
    line_unknown = b"0\ta\tmissing\n"
    line_empty_dependency = b"0\ta\t\n"
    line_negative_zero = b"-0\ta\n"
    line_control = "0\tbad\u200bnode\n".encode("utf-8")
    too_many_nodes = _line_graph(
        [(0, f"node-{index:02d}", []) for index in range(65)]
    )
    invalid_utf8 = b"0\tbad\xff\n"
    return (
        (
            "duplicate-json-root-key",
            "json-adjacency",
            "utf8-smallest",
            duplicate_root_key,
        ),
        (
            "floating-json-priority",
            "json-adjacency",
            "declared-priority",
            float_priority,
        ),
        (
            "boolean-json-priority",
            "json-adjacency",
            "declared-priority",
            bool_priority,
        ),
        (
            "negative-zero-json-priority",
            "json-adjacency",
            "declared-priority",
            negative_zero,
        ),
        (
            "lone-surrogate-identifier",
            "json-adjacency",
            "utf8-smallest",
            lone_surrogate,
        ),
        (
            "duplicate-node",
            "json-adjacency",
            "stable-input-order",
            duplicate_node,
        ),
        (
            "unknown-dependency",
            "json-adjacency",
            "shortest-depth",
            unknown_dependency,
        ),
        (
            "missing-json-final-lf",
            "json-adjacency",
            "utf8-smallest",
            _json_adjacency([("a", 0, [])])[:-1],
        ),
        (
            "json-crlf-framing",
            "json-adjacency",
            "utf8-smallest",
            _json_adjacency([("a", 0, [])])[:-1] + b"\r\n",
        ),
        (
            "wrong-csv-header",
            "csv-edges",
            "utf8-smallest",
            csv_header,
        ),
        (
            "bare-lf-csv",
            "csv-edges",
            "utf8-smallest",
            csv_lf,
        ),
        (
            "unterminated-csv-quote",
            "csv-edges",
            "utf8-smallest",
            csv_bad_quote,
        ),
        (
            "unquoted-csv-quote",
            "csv-edges",
            "utf8-smallest",
            csv_unquoted_quote,
        ),
        (
            "characters-after-csv-quote",
            "csv-edges",
            "utf8-smallest",
            csv_after_quote,
        ),
        (
            "duplicate-csv-node",
            "csv-edges",
            "stable-input-order",
            csv_duplicate,
        ),
        (
            "unknown-csv-endpoint",
            "csv-edges",
            "largest-fanout",
            csv_unknown,
        ),
        (
            "duplicate-line-node",
            "line-oriented-dependencies",
            "stable-input-order",
            line_duplicate,
        ),
        (
            "unknown-line-dependency",
            "line-oriented-dependencies",
            "shortest-depth",
            line_unknown,
        ),
        (
            "empty-line-dependency",
            "line-oriented-dependencies",
            "utf8-smallest",
            line_empty_dependency,
        ),
        (
            "negative-zero-line-priority",
            "line-oriented-dependencies",
            "declared-priority",
            line_negative_zero,
        ),
        (
            "format-control-line-id",
            "line-oriented-dependencies",
            "utf8-smallest",
            line_control,
        ),
        (
            "node-count-over-bound",
            "line-oriented-dependencies",
            "stable-input-order",
            too_many_nodes,
        ),
        (
            "invalid-utf8",
            "line-oriented-dependencies",
            "utf8-smallest",
            invalid_utf8,
        ),
    )


class DependencyDagExecutionPlanBashCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = dag.build_dependency_dag_execution_plan_tasks()

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
            "test_executable_dependency_dag_execution_plan_bash_canary "
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

    def test_exact_bounds_accept_at_limit_and_fail_above_limit(self) -> None:
        bash, tools = _binary_paths()
        (
            boundary_source,
            oversized_source,
            expected_boundary,
            maximum_source,
            oversized_maximum_source,
            repeated_512,
            repeated_513,
            unique_256,
            unique_257,
        ) = _boundary_vectors()
        vector = sha256(b"cbds.dependency-dag-boundary-vector.v1\0")
        for piece in (
            boundary_source,
            oversized_source,
            expected_boundary,
            maximum_source,
            oversized_maximum_source,
            repeated_512,
            repeated_513,
            unique_256,
            unique_257,
        ):
            _commit_piece(vector, piece)
        self.assertEqual(vector.hexdigest(), _BOUNDARY_VECTOR_SHA256)

        expected_maximum = _expected_output(
            "json-adjacency",
            "declared-priority",
            status="valid",
            node_count=1,
            edge_count=0,
            plan=["maximum-source"],
        )
        expected_repeated = _expected_output(
            "line-oriented-dependencies",
            "utf8-smallest",
            status="valid",
            node_count=2,
            edge_count=1,
            plan=["root", "dependent"],
        )
        expected_unique = _expected_output(
            "line-oriented-dependencies",
            "utf8-smallest",
            status="valid",
            node_count=64,
            edge_count=256,
            plan=[f"n{index:02d}" for index in range(64)],
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, tool_root = _write_fixed_canary(root, tools)
            valid_cases = (
                (
                    "identifier-128",
                    boundary_source,
                    "json-adjacency",
                    "declared-priority",
                    expected_boundary,
                ),
                (
                    "source-maximum",
                    maximum_source,
                    "json-adjacency",
                    "declared-priority",
                    expected_maximum,
                ),
                (
                    "physical-dependencies-512",
                    repeated_512,
                    "line-oriented-dependencies",
                    "utf8-smallest",
                    expected_repeated,
                ),
                (
                    "unique-edges-256-and-nodes-64",
                    unique_256,
                    "line-oriented-dependencies",
                    "utf8-smallest",
                    expected_unique,
                ),
            )
            for name, payload, encoding, policy, expected in valid_cases:
                workspace = root / name
                _materialize_manual_source(workspace, payload)
                completed = _run_fixed_canary(
                    bash,
                    script,
                    tool_root,
                    workspace,
                    encoding,
                    policy,
                )
                self.assertEqual(
                    completed.returncode,
                    0,
                    (name, completed.stdout + completed.stderr),
                )
                self.assertEqual(completed.stdout, b"", name)
                self.assertEqual(completed.stderr, b"", name)
                _require_manual_output(workspace, expected)

            invalid_cases = (
                (
                    "identifier-129",
                    oversized_source,
                    "json-adjacency",
                    "declared-priority",
                ),
                (
                    "source-maximum-plus-one",
                    oversized_maximum_source,
                    "json-adjacency",
                    "declared-priority",
                ),
                (
                    "physical-dependencies-513",
                    repeated_513,
                    "line-oriented-dependencies",
                    "utf8-smallest",
                ),
                (
                    "unique-edges-257",
                    unique_257,
                    "line-oriented-dependencies",
                    "utf8-smallest",
                ),
            )
            for name, payload, encoding, policy in invalid_cases:
                workspace = root / name
                _materialize_manual_source(workspace, payload)
                completed = _run_fixed_canary(
                    bash,
                    script,
                    tool_root,
                    workspace,
                    encoding,
                    policy,
                )
                self.assertNotEqual(completed.returncode, 0, name)
                self.assertEqual(completed.stdout, b"", name)
                self.assertEqual(completed.stderr, b"", name)
                self.assertFalse((workspace / "output").exists(), name)

    def test_cycle_residual_and_true_cycle_members_are_distinct(self) -> None:
        source = _line_graph(
            [
                (0, "cycle-a", ["cycle-b"]),
                (0, "cycle-b", ["cycle-a"]),
                (0, "downstream", ["cycle-b"]),
                (0, "self", ["self"]),
                (0, "ready", []),
                (0, "tail", ["ready"]),
            ]
        )
        expected = _expected_output(
            "line-oriented-dependencies",
            "largest-fanout",
            status="cycle",
            node_count=6,
            edge_count=5,
            plan=[],
            blocked_nodes=[
                "cycle-a",
                "cycle-b",
                "downstream",
                "self",
            ],
            cyclic_nodes=["cycle-a", "cycle-b", "self"],
        )
        bash, tools = _binary_paths()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, tool_root = _write_fixed_canary(root, tools)
            workspace = root / "cycle"
            _materialize_manual_source(workspace, source)
            completed = _run_fixed_canary(
                bash,
                script,
                tool_root,
                workspace,
                "line-oriented-dependencies",
                "largest-fanout",
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stdout + completed.stderr,
            )
            self.assertEqual(completed.stdout, b"")
            self.assertEqual(completed.stderr, b"")
            _require_manual_output(workspace, expected)

    def test_malformed_type_framing_and_partial_input_fail_closed(
        self,
    ) -> None:
        cases = _failure_cases()
        vector = sha256(b"cbds.dependency-dag-failure-vector.v1\0")
        for name, encoding, policy, payload in cases:
            for piece in (
                name.encode("ascii"),
                encoding.encode("ascii"),
                policy.encode("ascii"),
                payload,
            ):
                _commit_piece(vector, piece)
        self.assertEqual(vector.hexdigest(), _FAILURE_VECTOR_SHA256)

        bash, tools = _binary_paths()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, tool_root = _write_fixed_canary(root, tools)
            for index, (name, encoding, policy, payload) in enumerate(cases):
                workspace = root / f"failure-{index:02d}-{name}"
                _materialize_manual_source(workspace, payload)
                source = (
                    workspace
                    / dag.DEPENDENCY_DAG_EXECUTION_PLAN_INPUT
                )
                before = source.read_bytes()
                completed = _run_fixed_canary(
                    bash,
                    script,
                    tool_root,
                    workspace,
                    encoding,
                    policy,
                )
                self.assertNotEqual(completed.returncode, 0, name)
                self.assertEqual(completed.stdout, b"", name)
                self.assertEqual(completed.stderr, b"", name)
                self.assertFalse((workspace / "output").exists(), name)
                self.assertEqual(source.read_bytes(), before, name)

    def test_source_symlink_and_preexisting_output_fail_closed(self) -> None:
        source = _json_adjacency([("a", 0, [])])
        bash, tools = _binary_paths()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, tool_root = _write_fixed_canary(root, tools)

            symlink_workspace = root / "symlink-source"
            (symlink_workspace / "input").mkdir(parents=True)
            target = symlink_workspace / "graph-target"
            target.write_bytes(source)
            (
                symlink_workspace
                / dag.DEPENDENCY_DAG_EXECUTION_PLAN_INPUT
            ).symlink_to(target)
            symlink_run = _run_fixed_canary(
                bash,
                script,
                tool_root,
                symlink_workspace,
                "json-adjacency",
                "utf8-smallest",
            )
            self.assertNotEqual(symlink_run.returncode, 0)
            self.assertEqual(symlink_run.stdout, b"")
            self.assertEqual(symlink_run.stderr, b"")
            self.assertFalse((symlink_workspace / "output").exists())

            preexisting_workspace = root / "preexisting-output"
            _materialize_manual_source(preexisting_workspace, source)
            (preexisting_workspace / "output").mkdir()
            marker = preexisting_workspace / "output" / "marker"
            marker.write_bytes(b"preserve\n")
            preexisting_run = _run_fixed_canary(
                bash,
                script,
                tool_root,
                preexisting_workspace,
                "json-adjacency",
                "utf8-smallest",
            )
            self.assertNotEqual(preexisting_run.returncode, 0)
            self.assertEqual(preexisting_run.stdout, b"")
            self.assertEqual(preexisting_run.stderr, b"")
            self.assertEqual(marker.read_bytes(), b"preserve\n")

    def test_argument_domain_is_exact_and_quiet(self) -> None:
        source = _json_adjacency([("a", 0, [])])
        bash, tools = _binary_paths()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, tool_root = _write_fixed_canary(root, tools)
            cases = (
                (),
                ("json-adjacency",),
                ("unknown", "utf8-smallest"),
                ("json-adjacency", "unknown"),
                (
                    "json-adjacency",
                    "utf8-smallest",
                    "ignored-extra",
                ),
            )
            for index, arguments in enumerate(cases):
                workspace = root / f"arguments-{index}"
                _materialize_manual_source(workspace, source)
                completed = subprocess.run(
                    [
                        bash,
                        "--noprofile",
                        "--norc",
                        str(script),
                        *arguments,
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
                self.assertNotEqual(completed.returncode, 0, arguments)
                self.assertEqual(completed.stdout, b"", arguments)
                self.assertEqual(completed.stderr, b"", arguments)
                self.assertFalse((workspace / "output").exists(), arguments)

    def test_literal_hash_tool_budget_vectors_and_nonclaim_boundary(
        self,
    ) -> None:
        self.assertEqual(
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_ALLOWED_TOOLS,
            ("mkdir", "python3"),
        )
        self.assertEqual(
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_GRAPH_ENCODINGS,
            (
                "json-adjacency",
                "json-edge-list",
                "csv-edges",
                "line-oriented-dependencies",
            ),
        )
        self.assertEqual(
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_TIE_BREAK_POLICIES,
            (
                "utf8-smallest",
                "declared-priority",
                "shortest-depth",
                "largest-fanout",
                "stable-input-order",
            ),
        )
        self.assertEqual(
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_INPUT,
            "input/graph.data",
        )
        self.assertEqual(
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT,
            "output/execution-plan.json",
        )
        self.assertEqual(
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_MODE,
            0o644,
        )
        self.assertEqual(
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_SOURCE_MAXIMUM_BYTES,
            128 * 1024,
        )
        self.assertEqual(
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_NODES,
            64,
        )
        self.assertEqual(
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_PHYSICAL_DEPENDENCIES,
            512,
        )
        self.assertEqual(
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_MAXIMUM_EDGES,
            256,
        )
        self.assertEqual(
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_JSON_MAXIMUM_DEPTH,
            8,
        )
        self.assertEqual(
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_JSON_MAXIMUM_NODES,
            4096,
        )
        self.assertEqual(
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_NODE_ID_MAXIMUM_UTF8_BYTES,
            128,
        )
        self.assertEqual(
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_PRIORITY_MAXIMUM,
            1_000_000,
        )
        self.assertEqual(
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_OUTPUT_MAXIMUM_BYTES,
            64 * 1024,
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
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_FINAL_OUTPUT_OBSERVED,
            True,
        )
        self.assertIs(
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_INPUT_PRESERVATION_OBSERVED,
            True,
        )
        self.assertIs(
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE,
            True,
        )
        for boundary in (
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_ATOMICITY_OBSERVED,
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_TOOL_HISTORY_OBSERVED,
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_READ_SCOPE_OBSERVED,
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_CANDIDATE_EXIT_STATUS_OBSERVED,
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_TRANSIENT_STATE_OBSERVED,
            dag.DEPENDENCY_DAG_EXECUTION_PLAN_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
        ):
            self.assertIs(boundary, False)

        self.assertNotIn("/usr/bin/", _HAND_AUTHORED_BASH)
        self.assertNotIn("/bin/", _HAND_AUTHORED_BASH)
        self.assertNotIn("subprocess", _HAND_AUTHORED_BASH)
        self.assertNotIn("socket", _HAND_AUTHORED_BASH)
        self.assertNotIn("eval ", _HAND_AUTHORED_BASH)
        self.assertNotIn("exec(", _HAND_AUTHORED_BASH)
        self.assertIn(
            'if [[ $# -ne 2 ]]; then',
            _HAND_AUTHORED_BASH,
        )
        self.assertIn(
            'graph_encoding=$1',
            _HAND_AUTHORED_BASH,
        )
        self.assertIn(
            'tie_break_policy=$2',
            _HAND_AUTHORED_BASH,
        )
        self.assertIn(
            'python3 -I -S - "$graph_encoding" "$tie_break_policy"',
            _HAND_AUTHORED_BASH,
        )
        self.assertIn('INPUT = "input/graph.data"', _HAND_AUTHORED_BASH)
        self.assertIn(
            'OUTPUT = "output/execution-plan.json"',
            _HAND_AUTHORED_BASH,
        )
        self.assertIn('os.mkdir("output", 0o755)', _HAND_AUTHORED_BASH)
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
