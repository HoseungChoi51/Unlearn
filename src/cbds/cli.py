"""Command-line interface for reproducible CBDS experiment preparation.

The foundation release executes data preparation, response validation, sandbox
command construction, and result validation.  Training and compression commands
currently produce validated, content-addressed run plans; they deliberately do
not claim to execute GPU work until a backend is added.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, is_dataclass
from enum import Enum
from hashlib import sha256
import json
from pathlib import Path
import sys
from typing import Any, Callable, Mapping, Sequence

from . import __version__


class CliError(ValueError):
    """An expected, user-actionable CLI error."""


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _emit(value: Any, output: Path | None = None) -> None:
    document = _jsonable(value)
    if output is None:
        print(json.dumps(document, sort_keys=True, separators=(",", ":")))
        return

    from .manifests import atomic_write_json

    atomic_write_json(output, document)


def _validate_stage_record(stage: str, manifest_path: Path, output: Path) -> None:
    from .manifests import (
        canonical_json_bytes,
        load_experiment_manifest,
        value_sha256,
    )

    manifest = load_experiment_manifest(manifest_path)
    manifest_sha256 = value_sha256(manifest)
    identity = value_sha256({"manifest_sha256": manifest_sha256, "stage": stage})
    record = {
        "schema_version": "1.0.0",
        "validation_id": f"{stage}-{identity[:20]}",
        "stage": stage,
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_sha256,
        "manifest_kind": "completed_experiment_record",
        "validation_status": "valid",
        "execution_status": "not_executed",
        "execution_backend": None,
        "message": (
            "The completed-record manifest is valid. A prospective run-spec "
            f"contract and the {stage} execution backend are not implemented."
        ),
    }
    # Force canonical serialization before the atomic write so non-JSON values
    # cannot enter a content-addressed validation record.
    canonical_json_bytes(record)
    _emit(record, output)


def _require_complete_benchmark_config(config: Any) -> Mapping[str, Any]:
    """Reject CLI configs that rely on library defaults.

    Small defaults remain useful for direct unit-level APIs, but experiment
    commands must make every resolved preparation choice explicit.
    """

    from .benchmark import SPLIT_NAMES

    if not isinstance(config, Mapping):
        raise CliError("benchmark config must be a JSON or YAML object")
    required = {"seed", "fixture_count", "family_size", "static", "interactive"}
    missing = required.difference(config)
    if missing:
        raise CliError(
            "benchmark config omits required explicit fields: "
            + ", ".join(sorted(missing))
        )
    for suite in ("static", "interactive"):
        counts = config[suite]
        if not isinstance(counts, Mapping):
            raise CliError(f"benchmark config field {suite!r} must be an object")
        missing_splits = set(SPLIT_NAMES).difference(counts)
        if missing_splits:
            raise CliError(
                f"benchmark config field {suite!r} omits split counts: "
                + ", ".join(sorted(missing_splits))
            )
    return config


def _cmd_prepare(args: argparse.Namespace) -> None:
    from .benchmark import prepare_benchmark
    from .manifests import load_document

    config = _require_complete_benchmark_config(load_document(args.config))
    result = prepare_benchmark(config, args.output_dir)
    _emit(result, args.summary)


def _cmd_stage_plan(args: argparse.Namespace) -> None:
    if not args.dry_run:
        raise CliError(
            f"{args.command} execution is not implemented yet; use --dry-run "
            "to validate and content-address the manifest"
        )
    _validate_stage_record(args.command, args.manifest, args.output)


def _cmd_evaluate(args: argparse.Namespace) -> None:
    from .response import check_syntax, parse_response

    payload = args.response.read_bytes()
    text = payload.decode("utf-8")
    parsed = parse_response(
        text,
        max_bytes=args.max_bytes,
        was_truncated=args.was_truncated,
    )
    syntax = check_syntax(
        parsed,
        bash_executable=args.bash_executable,
        timeout_seconds=args.syntax_timeout,
    )
    _emit(
        {
            "schema_version": "1.0.0",
            "response_sha256": sha256(payload).hexdigest(),
            "policy": {
                "response_grammar": "raw-or-one-triple-backtick-fence",
                "max_response_bytes": args.max_bytes,
                "external_truncation_reported": args.was_truncated,
                "bash_executable": args.bash_executable,
                "syntax_timeout_seconds": args.syntax_timeout,
                "executes_program": False,
            },
            "parsed": parsed,
            "syntax": syntax,
        },
        args.output,
    )


def _cmd_bench_validate(args: argparse.Namespace) -> None:
    from .manifests import load_document, validate_hardware_result

    validated = []
    for path in args.results:
        document = load_document(path)
        validate_hardware_result(document, schema_path=args.schema)
        validated.append(
            {
                "path": str(path),
                "run_id": document["run_id"],
                "schema_version": document["schema_version"],
                "valid": True,
            }
        )
    _emit({"results": validated}, args.output)


def _cmd_merge_results(args: argparse.Namespace) -> None:
    from .manifests import merge_hardware_results

    merged = merge_hardware_results(args.results, schema_path=args.schema)
    _emit(merged, args.output)


def _cmd_sandbox_command(args: argparse.Namespace) -> None:
    from .response import ProgramLanguage
    from .sandbox import SandboxConfig, build_sandbox_argv

    config = SandboxConfig(
        image=args.image,
        runtime=args.engine,
        timeout_seconds=args.timeout,
        memory_bytes=args.memory_bytes,
        cpu_count=args.cpus,
        pids_limit=args.pids,
        output_bytes=args.output_limit_bytes,
        uid=args.uid,
        gid=args.gid,
    )
    language = ProgramLanguage(args.language)
    argv = build_sandbox_argv(config, language)
    _emit(
        {
            "argv": argv,
            "config": config,
            "language": language,
            "program_transport": "stdin",
            "executed": False,
        },
        args.output,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cbds",
        description="Capability-budgeted dense specialization research tools",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser(
        "prepare", help="generate deterministic benchmark artifacts"
    )
    prepare.add_argument("--config", type=Path, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)
    prepare.add_argument("--summary", type=Path)
    prepare.set_defaults(handler=_cmd_prepare)

    for stage in ("train", "compress"):
        command = subparsers.add_parser(
            stage,
            help=(
                "validate and content-address a completed experiment record; "
                f"the {stage} backend is not yet implemented"
            ),
        )
        command.add_argument("--manifest", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--dry-run", action="store_true")
        command.set_defaults(handler=_cmd_stage_plan)

    evaluate = subparsers.add_parser(
        "evaluate", help="apply the frozen response parser and syntax gate"
    )
    evaluate.add_argument("--response", type=Path, required=True)
    evaluate.add_argument("--output", type=Path)
    evaluate.add_argument("--max-bytes", type=int, default=65536)
    evaluate.add_argument("--was-truncated", action="store_true")
    evaluate.add_argument("--bash-executable", default="bash")
    evaluate.add_argument("--syntax-timeout", type=float, default=5.0)
    evaluate.set_defaults(handler=_cmd_evaluate)

    bench = subparsers.add_parser(
        "bench-hardware", help="validate portable hardware result documents"
    )
    bench_subparsers = bench.add_subparsers(dest="bench_command", required=True)
    validate = bench_subparsers.add_parser("validate")
    validate.add_argument("results", nargs="+", type=Path)
    validate.add_argument("--schema", type=Path)
    validate.add_argument("--output", type=Path)
    validate.set_defaults(handler=_cmd_bench_validate)

    merge = subparsers.add_parser(
        "merge-results", help="validate and group hardware results by stratum"
    )
    merge.add_argument("results", nargs="+", type=Path)
    merge.add_argument("--schema", type=Path)
    merge.add_argument("--output", type=Path, required=True)
    merge.set_defaults(handler=_cmd_merge_results)

    sandbox = subparsers.add_parser(
        "sandbox-command",
        help="construct a hardened stdin-driven container command without running it",
    )
    sandbox.add_argument("--engine", choices=("docker", "podman"), required=True)
    sandbox.add_argument("--image", required=True)
    sandbox.add_argument("--language", choices=("bash", "python"), default="bash")
    sandbox.add_argument("--timeout", type=int, default=10)
    sandbox.add_argument("--memory-bytes", type=int, default=536870912)
    sandbox.add_argument("--cpus", type=float, default=1.0)
    sandbox.add_argument("--pids", type=int, default=64)
    sandbox.add_argument("--output-limit-bytes", type=int, default=1048576)
    sandbox.add_argument("--uid", type=int, default=65534)
    sandbox.add_argument("--gid", type=int, default=65534)
    sandbox.add_argument("--output", type=Path)
    sandbox.set_defaults(handler=_cmd_sandbox_command)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        handler: Callable[[argparse.Namespace], None] = args.handler
        handler(args)
    except (CliError, OSError, ValueError) as exc:
        error = {
            "error": type(exc).__name__,
            "message": str(exc),
        }
        print(json.dumps(error, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 2
    return 0


__all__ = ["CliError", "build_parser", "main"]
