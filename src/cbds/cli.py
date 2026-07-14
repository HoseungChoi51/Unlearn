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
import os
from pathlib import Path
import stat
import sys
from typing import Any, Callable, Mapping, Sequence

from . import __version__


class CliError(ValueError):
    """An expected, user-actionable CLI error."""


_BENCHMARK_VERIFY_LIMITS = {
    "max_manifest_bytes": 1024 * 1024,
    "max_inventory_entries": 100_000,
    "max_total_records": 100_000,
    "max_total_fixtures": 1_000_000,
    "max_total_jsonl_bytes": 256 * 1024 * 1024,
}
_MAX_DIAGNOSTIC_RESPONSE_FILE_BYTES = 256 * 1024 * 1024


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


def _paths_alias(left: Path, right: Path) -> bool:
    try:
        if left.resolve() == right.resolve():
            return True
    except OSError:
        pass
    try:
        return os.path.samefile(left, right)
    except OSError:
        return False


def _path_within(path: Path, directory: Path) -> bool:
    """Return whether *path* resolves to *directory* or one of its children."""

    try:
        resolved_path = path.resolve(strict=False)
        resolved_directory = directory.resolve(strict=False)
    except (OSError, RuntimeError):
        resolved_path = Path(os.path.abspath(path))
        resolved_directory = Path(os.path.abspath(directory))
    return (
        resolved_path == resolved_directory
        or resolved_directory in resolved_path.parents
    )


def _reject_output_aliases(
    output: Path | None,
    inputs: Sequence[tuple[str, Path | None]],
) -> None:
    """Prevent an output write from replacing any source document."""

    if output is None:
        return
    for label, source in inputs:
        if source is not None and _paths_alias(source, output):
            raise CliError(f"--output must not resolve to {label} or its inode")


def _read_hashed_response(path: Path, retain_bytes: int) -> tuple[bytes, int, str]:
    """Hash a stable response while retaining at most the parser byte limit."""

    digest = sha256()
    retained = bytearray()
    total = 0
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        flags |= nofollow
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb", buffering=0) as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise CliError("response input must be a regular file")
        if before.st_size > _MAX_DIAGNOSTIC_RESPONSE_FILE_BYTES:
            raise CliError("response file exceeds the diagnostic scan limit")
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_DIAGNOSTIC_RESPONSE_FILE_BYTES:
                raise CliError("response file grew beyond the diagnostic scan limit")
            digest.update(chunk)
            available = retain_bytes - len(retained)
            if available > 0:
                retained.extend(chunk[:available])
        after = os.fstat(handle.fileno())
    fingerprint = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if fingerprint(before) != fingerprint(after) or total != before.st_size:
        raise CliError("response file changed while it was being read")
    return bytes(retained), total, digest.hexdigest()


def _stage_plan(
    stage: str,
    run_spec_path: Path,
    campaign_policy_path: Path,
    output: Path,
) -> None:
    from .manifests import canonical_json_bytes, value_sha256
    from .run_specs import (
        campaign_policy_sha256,
        load_campaign_policy,
        load_run_spec,
        run_spec_sha256,
        validate_run_spec_against_campaign,
    )

    if _paths_alias(run_spec_path, output):
        raise CliError("--output must not resolve to the --run-spec file or inode")
    if _paths_alias(campaign_policy_path, output):
        raise CliError(
            "--output must not resolve to the --campaign-policy file or inode"
        )

    run_spec = load_run_spec(run_spec_path)
    campaign_policy = load_campaign_policy(campaign_policy_path)
    validate_run_spec_against_campaign(run_spec, campaign_policy)
    if run_spec["stage"] != stage:
        raise CliError(
            f"run spec stage {run_spec['stage']!r} does not match command {stage!r}"
        )
    spec_sha256 = run_spec_sha256(run_spec)
    policy_sha256 = campaign_policy_sha256(campaign_policy)
    identity = value_sha256(
        {
            "campaign_policy_sha256": policy_sha256,
            "run_spec_sha256": spec_sha256,
            "stage": stage,
        }
    )
    record = {
        "schema_version": "2.0.0",
        "plan_id": f"{stage}-{identity[:20]}",
        "planned_run_id": run_spec["run_id"],
        "stage": stage,
        "run_spec_path": str(run_spec_path),
        "run_spec_sha256": spec_sha256,
        "campaign_policy_path": str(campaign_policy_path),
        "campaign_policy_schema_version": campaign_policy["schema_version"],
        "campaign_policy_sha256": policy_sha256,
        "campaign_profile": run_spec["campaign"]["profile"],
        "campaign_replicate_index": run_spec["campaign"]["replicate_index"],
        "campaign_declared_seed_count": run_spec["campaign"][
            "declared_seed_count"
        ],
        "manifest_kind": "prospective_run_spec",
        "validation_status": "valid",
        "execution_status": "validated_plan",
        "execution_backend": None,
        "message": (
            "The prospective run spec is valid. This foundation milestone "
            f"does not yet execute the {stage} backend."
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

    if _path_within(args.config, args.output_dir):
        raise CliError("--config must not be inside --output-dir")
    if args.summary is not None:
        if _paths_alias(args.config, args.summary):
            raise CliError("--summary must not resolve to --config or its inode")
        if _path_within(args.summary, args.output_dir):
            raise CliError("--summary must be outside --output-dir")
    config = _require_complete_benchmark_config(load_document(args.config))
    result = prepare_benchmark(config, args.output_dir)
    _emit(result, args.summary)


def _cmd_stage_plan(args: argparse.Namespace) -> None:
    if not args.dry_run:
        raise CliError(
            f"{args.command} execution is not implemented yet; use --dry-run "
            "to validate and content-address the run spec"
        )
    _stage_plan(args.command, args.run_spec, args.campaign_policy, args.output)


def _cmd_validate_run_spec(args: argparse.Namespace) -> None:
    """Validate a prospective spec without claiming campaign qualification."""

    from .run_specs import load_run_spec, run_spec_sha256

    _reject_output_aliases(
        args.output,
        (("--run-spec", args.run_spec), ("--schema", args.schema)),
    )
    spec = load_run_spec(args.run_spec, schema_path=args.schema)
    _emit(
        {
            "schema_version": "1.0.0",
            "valid": True,
            "run_id": spec["run_id"],
            "stage": spec["stage"],
            "run_spec_schema_version": spec["schema_version"],
            "run_spec_sha256": run_spec_sha256(spec, schema_path=args.schema),
            "campaign_qualified": False,
            "validation_scope": "run_spec_schema_and_semantics_only",
            "execution_status": "not_executed",
        },
        args.output,
    )


def _cmd_validate_experiment_record(args: argparse.Namespace) -> None:
    from .manifests import load_document, value_sha256
    from .run_specs import (
        campaign_policy_sha256,
        load_campaign_policy,
        load_run_spec,
        validate_completed_run_against_campaign,
    )

    _reject_output_aliases(
        args.output,
        (
            ("--manifest", args.manifest),
            ("--run-spec", args.run_spec),
            ("--campaign-policy", args.campaign_policy),
            ("--schema", args.schema),
        ),
    )
    policy = load_campaign_policy(args.campaign_policy)
    spec = load_run_spec(args.run_spec)
    record = validate_completed_run_against_campaign(
        spec,
        policy,
        load_document(args.manifest),
        experiment_schema_path=args.schema,
    )
    _emit(
        {
            "schema_version": "2.0.0",
            "valid": True,
            "binding_status": "bound_to_prospective_run_spec",
            "manifest_kind": "completed_experiment_record",
            "experiment_id": record["experiment_id"],
            "run_id": record["run_id"],
            "stage": record["stage"],
            "run_spec_schema_version": record["run_spec_schema_version"],
            "run_spec_sha256": record["run_spec_sha256"],
            "campaign_policy_schema_version": policy["schema_version"],
            "campaign_policy_sha256": campaign_policy_sha256(policy),
            "campaign_profile": spec["campaign"]["profile"],
            "campaign_replicate_index": spec["campaign"]["replicate_index"],
            "campaign_declared_seed_count": spec["campaign"][
                "declared_seed_count"
            ],
            "manifest_sha256": value_sha256(record),
        },
        args.output,
    )


def _cmd_verify_benchmark(args: argparse.Namespace) -> None:
    from .benchmark_artifacts import validate_benchmark_artifacts

    if args.output is not None and _path_within(args.output, args.dataset_dir):
        raise CliError("--output must be outside --dataset-dir")
    summary = validate_benchmark_artifacts(
        args.dataset_dir,
        expected_dataset_sha256=args.expected_dataset_sha256,
        expected_manifest_sha256=args.expected_manifest_sha256,
        reject_extra_files=not args.allow_extra_files,
        **_BENCHMARK_VERIFY_LIMITS,
    )
    summary["verification_policy"] = {
        **_BENCHMARK_VERIFY_LIMITS,
        "reject_extra_files": not args.allow_extra_files,
        "external_dataset_digest_required": args.expected_dataset_sha256 is not None,
        "external_manifest_digest_required": args.expected_manifest_sha256 is not None,
    }
    _emit(summary, args.output)


def _cmd_evaluate(args: argparse.Namespace) -> None:
    from .evaluation_specs import evaluation_spec_sha256, load_evaluation_spec
    from .response import (
        PYTHON_FEATURE_VERSION,
        ResponseStatus,
        check_syntax,
        identify_bash_checker,
        parse_response,
    )

    _reject_output_aliases(
        args.output,
        (
            ("--response", args.response),
            ("--evaluation-spec", args.evaluation_spec),
            ("--schema", args.schema),
        ),
    )
    spec = load_evaluation_spec(args.evaluation_spec, schema_path=args.schema)
    maximum_response_bytes = spec["limits"]["maximum_response_bytes"]
    payload, response_bytes, response_sha256 = _read_hashed_response(
        args.response, maximum_response_bytes
    )
    oversized = response_bytes > maximum_response_bytes
    if oversized:
        text = ""
    else:
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            # Surrogates make the frozen parser return extraction_failure while
            # preserving the exact raw-byte hash in the diagnostic record.
            text = payload.decode("utf-8", errors="surrogateescape")
    parsed = parse_response(
        text,
        max_bytes=maximum_response_bytes,
        was_truncated=args.was_truncated or oversized,
    )
    required_language = spec["parser"]["program_language"]
    language_matches = parsed.language.value == required_language
    syntax = (
        check_syntax(
            parsed,
            bash_executable=args.bash_executable,
            timeout_seconds=spec["limits"]["syntax_timeout_seconds"],
        )
        if language_matches
        else None
    )
    bash_identity = identify_bash_checker(args.bash_executable)

    code_sha256 = (
        sha256(parsed.code.encode("utf-8")).hexdigest()
        if parsed.code is not None
        else None
    )
    parsed_detail_sha256 = (
        sha256(parsed.detail.encode("utf-8")).hexdigest()
        if parsed.detail is not None
        else None
    )
    if syntax is None:
        mismatch = (
            f"parsed response language {parsed.language.value!r} does not match "
            f"required language {required_language!r}"
        )
        syntax_record: Mapping[str, Any] = {
            "status": ResponseStatus.EXTRACTION_FAILURE.value,
            "language": parsed.language.value,
            "detail_sha256": sha256(mismatch.encode("utf-8")).hexdigest(),
            "return_code": None,
        }
    else:
        syntax_record = {
            "status": syntax.status.value,
            "language": syntax.language.value,
            "detail_sha256": (
                sha256(syntax.detail.encode("utf-8")).hexdigest()
                if syntax.detail is not None
                else None
            ),
            "return_code": syntax.return_code,
        }
    _emit(
        {
            "schema_version": "1.0.0",
            "evaluation_id": spec["evaluation_id"],
            "evaluation_spec_sha256": evaluation_spec_sha256(
                spec, schema_path=args.schema
            ),
            "response_sha256": response_sha256,
            "response_bytes": response_bytes,
            "policy": {
                "response_grammar": spec["parser"]["grammar"],
                "parser_version": spec["parser"]["version"],
                "required_language": required_language,
                "language_matches": language_matches,
                "max_response_bytes": maximum_response_bytes,
                "external_truncation_reported": args.was_truncated,
                "response_limit_exceeded": oversized,
                "diagnostic_scan_limit_bytes": (
                    _MAX_DIAGNOSTIC_RESPONSE_FILE_BYTES
                ),
                "bash_executable": args.bash_executable,
                "bash_checker_identity": bash_identity,
                "syntax_timeout_seconds": spec["limits"][
                    "syntax_timeout_seconds"
                ],
                "python_feature_version": list(PYTHON_FEATURE_VERSION),
                "syntax_environment": "host_diagnostic_only",
                "scored_evaluation_eligible": False,
                "executes_program": False,
                "retains_plaintext": False,
            },
            "parsed": {
                "status": parsed.status.value,
                "language": parsed.language.value,
                "detail_sha256": parsed_detail_sha256,
                "response_bytes": response_bytes,
                "code_bytes": parsed.code_bytes,
                "code_sha256": code_sha256,
                "fenced": parsed.fenced,
            },
            "syntax": syntax_record,
        },
        args.output,
    )


def _cmd_validate_evaluation_spec(args: argparse.Namespace) -> None:
    from .evaluation_specs import (
        evaluation_spec_sha256,
        load_evaluation_spec,
        validate_evaluation_spec_against_experiment_manifest,
    )
    from .manifests import load_document, value_sha256

    if args.experiment_schema is not None and args.experiment_manifest is None:
        raise CliError("--experiment-schema requires --experiment-manifest")
    _reject_output_aliases(
        args.output,
        (
            ("--evaluation-spec", args.evaluation_spec),
            ("--schema", args.schema),
            ("--experiment-manifest", args.experiment_manifest),
            ("--experiment-schema", args.experiment_schema),
        ),
    )
    spec = load_evaluation_spec(args.evaluation_spec, schema_path=args.schema)
    if args.experiment_manifest is None:
        binding_status = "unbound_prospective_hashes_only"
        completed_record_sha256 = None
    else:
        completed_record = load_document(args.experiment_manifest)
        validate_evaluation_spec_against_experiment_manifest(
            spec,
            completed_record,
            evaluation_schema_path=args.schema,
            experiment_schema_path=args.experiment_schema,
        )
        binding_status = "bound_to_completed_experiment_record"
        completed_record_sha256 = value_sha256(completed_record)
    _emit(
        {
            "schema_version": "1.0.0",
            "valid": True,
            "evaluation_id": spec["evaluation_id"],
            "mode": spec["mode"],
            "split_role": spec["benchmark"]["split"]["role"],
            "sealed": spec["benchmark"]["split"]["sealed"],
            "artifact_binding_status": binding_status,
            "completed_experiment_record_sha256": completed_record_sha256,
            "evaluation_spec_sha256": evaluation_spec_sha256(
                spec, schema_path=args.schema
            ),
        },
        args.output,
    )


def _cmd_inspect_model(args: argparse.Namespace) -> None:
    from .model_artifacts import inspect_model_artifact

    if args.output is not None and _path_within(args.output, args.artifact_dir):
        raise CliError("--output must be outside --artifact-dir")
    _emit(inspect_model_artifact(args.artifact_dir), args.output)


def _cmd_probe_model_runtime(args: argparse.Namespace) -> None:
    from .model_runtime import (
        MAX_PROMPT_UTF8_BYTES,
        ModelRuntimeProbeError,
        probe_local_causal_lm,
        verify_runtime_report_sha256,
    )

    if _path_within(args.prompt_file, args.artifact_dir):
        raise CliError("--prompt-file must be outside --artifact-dir")
    if args.output is not None:
        if _path_within(args.output, args.artifact_dir):
            raise CliError("--output must be outside --artifact-dir")
        if _paths_alias(args.output, args.prompt_file):
            raise CliError("--output must not resolve to --prompt-file or its inode")
    retained, total_bytes, _ = _read_hashed_response(
        args.prompt_file, MAX_PROMPT_UTF8_BYTES + 1
    )
    if total_bytes > MAX_PROMPT_UTF8_BYTES:
        raise CliError(
            f"--prompt-file exceeds the {MAX_PROMPT_UTF8_BYTES}-byte runtime limit"
        )
    try:
        prompt = retained.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise CliError("--prompt-file must contain valid UTF-8") from error
    try:
        report = probe_local_causal_lm(
            args.artifact_dir,
            prompt,
            token_cap=args.token_cap,
            device=args.device,
        )
    except ModelRuntimeProbeError as error:
        raise CliError(str(error)) from error
    try:
        report_hash_valid = verify_runtime_report_sha256(report)
    except (TypeError, ValueError, OverflowError) as error:
        raise CliError("runtime probe returned an invalid report") from error
    if not report_hash_valid:
        raise CliError("runtime probe returned an invalid report hash")
    _emit(report, args.output)


def _cmd_bench_validate(args: argparse.Namespace) -> None:
    from .manifests import (
        load_document,
        validate_hardware_result,
        validate_hardware_result_against_experiment_manifest,
        value_sha256,
    )

    _reject_output_aliases(
        args.output,
        tuple(("a hardware result input", path) for path in args.results)
        + (
            ("--schema", args.schema),
            ("--experiment-manifest", args.experiment_manifest),
        ),
    )
    completed_record = (
        load_document(args.experiment_manifest)
        if args.experiment_manifest is not None
        else None
    )
    validated = []
    for path in args.results:
        document = load_document(path)
        if completed_record is None:
            validated_document = validate_hardware_result(
                document,
                schema_path=args.schema,
            )
            binding_status = "unbound_standalone_validation"
            completed_manifest_sha256 = None
        else:
            validated_document = validate_hardware_result_against_experiment_manifest(
                document,
                completed_record,
                hardware_schema_path=args.schema,
            )
            binding_status = "bound_to_completed_experiment_manifest"
            completed_manifest_sha256 = value_sha256(completed_record)
        validated.append(
            {
                "path": str(path),
                "run_id": validated_document["run_id"],
                "schema_version": validated_document["schema_version"],
                "valid": True,
                "binding_status": binding_status,
                "completed_experiment_manifest_sha256": completed_manifest_sha256,
            }
        )
    _emit({"results": validated}, args.output)


def _cmd_merge_results(args: argparse.Namespace) -> None:
    from .manifests import merge_hardware_results

    _reject_output_aliases(
        args.output,
        tuple(("a hardware result input", path) for path in args.results)
        + (("--schema", args.schema),),
    )
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


def _cmd_sandbox_preflight(args: argparse.Namespace) -> None:
    from .runtime_preflight import inspect_container_runtime

    _emit(inspect_container_runtime(args.engine, args.image), args.output)


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

    verify_benchmark = subparsers.add_parser(
        "verify-benchmark",
        help="verify a generated benchmark directory and every declared record",
    )
    verify_benchmark.add_argument("--dataset-dir", type=Path, required=True)
    verify_benchmark.add_argument("--expected-dataset-sha256")
    verify_benchmark.add_argument("--expected-manifest-sha256")
    verify_benchmark.add_argument("--allow-extra-files", action="store_true")
    verify_benchmark.add_argument("--output", type=Path)
    verify_benchmark.set_defaults(handler=_cmd_verify_benchmark)

    for stage in ("train", "compress"):
        command = subparsers.add_parser(
            stage,
            help=(
                "validate and content-address a prospective run spec; "
                f"the {stage} backend is not yet implemented"
            ),
        )
        command.add_argument(
            "--run-spec",
            "--manifest",
            dest="run_spec",
            type=Path,
            required=True,
        )
        command.add_argument("--campaign-policy", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--dry-run", action="store_true")
        command.set_defaults(handler=_cmd_stage_plan)

    validate_run = subparsers.add_parser(
        "validate-run-spec",
        help=(
            "validate and hash a prospective run spec without claiming that "
            "it satisfies a campaign profile"
        ),
    )
    validate_run.add_argument("--run-spec", type=Path, required=True)
    validate_run.add_argument("--schema", type=Path)
    validate_run.add_argument("--output", type=Path)
    validate_run.set_defaults(handler=_cmd_validate_run_spec)

    validate_experiment = subparsers.add_parser(
        "validate-experiment-record",
        help=(
            "bind a completed experiment record to its prospective run spec and "
            "campaign policy, then report their content hashes"
        ),
    )
    validate_experiment.add_argument("--manifest", type=Path, required=True)
    validate_experiment.add_argument("--run-spec", type=Path, required=True)
    validate_experiment.add_argument("--campaign-policy", type=Path, required=True)
    validate_experiment.add_argument("--schema", type=Path)
    validate_experiment.add_argument("--output", type=Path)
    validate_experiment.set_defaults(handler=_cmd_validate_experiment_record)

    evaluate = subparsers.add_parser(
        "evaluate",
        help=(
            "apply an evaluation spec's response and host syntax gates; "
            "never execute or score the program"
        ),
    )
    evaluate.add_argument("--response", type=Path, required=True)
    evaluate.add_argument("--evaluation-spec", type=Path, required=True)
    evaluate.add_argument("--schema", type=Path)
    evaluate.add_argument("--output", type=Path)
    evaluate.add_argument("--was-truncated", action="store_true")
    evaluate.add_argument("--bash-executable", default="bash")
    evaluate.set_defaults(handler=_cmd_evaluate)

    validate_evaluation = subparsers.add_parser(
        "validate-evaluation-spec",
        help="validate and content-address a prospective evaluation contract",
    )
    validate_evaluation.add_argument("--evaluation-spec", type=Path, required=True)
    validate_evaluation.add_argument("--schema", type=Path)
    validate_evaluation.add_argument("--experiment-manifest", type=Path)
    validate_evaluation.add_argument("--experiment-schema", type=Path)
    validate_evaluation.add_argument("--output", type=Path)
    validate_evaluation.set_defaults(handler=_cmd_validate_evaluation_spec)

    inspect_model = subparsers.add_parser(
        "inspect-model",
        help="inspect a flat local Safetensors artifact without loading model code",
    )
    inspect_model.add_argument("--artifact-dir", type=Path, required=True)
    inspect_model.add_argument("--output", type=Path)
    inspect_model.set_defaults(handler=_cmd_inspect_model)

    probe_model = subparsers.add_parser(
        "probe-model-runtime",
        help=(
            "load a flat local Safetensors causal LM and run one bounded "
            "non-generative forward pass"
        ),
    )
    probe_model.add_argument("--artifact-dir", type=Path, required=True)
    probe_model.add_argument("--prompt-file", type=Path, required=True)
    probe_model.add_argument("--token-cap", type=int, required=True)
    probe_model.add_argument("--device", default="cpu")
    probe_model.add_argument("--output", type=Path)
    probe_model.set_defaults(handler=_cmd_probe_model_runtime)

    bench = subparsers.add_parser(
        "bench-hardware", help="validate portable hardware result documents"
    )
    bench_subparsers = bench.add_subparsers(dest="bench_command", required=True)
    validate = bench_subparsers.add_parser("validate")
    validate.add_argument("results", nargs="+", type=Path)
    validate.add_argument("--experiment-manifest", type=Path)
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

    preflight = subparsers.add_parser(
        "sandbox-preflight",
        help=(
            "inspect rootless-runtime and local-image readiness without "
            "starting or pulling a container"
        ),
    )
    preflight.add_argument("--engine", choices=("docker", "podman"), required=True)
    preflight.add_argument("--image", required=True)
    preflight.add_argument("--output", type=Path)
    preflight.set_defaults(handler=_cmd_sandbox_preflight)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        handler: Callable[[argparse.Namespace], None] = args.handler
        handler(args)
    except (CliError, OSError, OverflowError, ValueError) as exc:
        error = {
            "error": type(exc).__name__,
            "message": str(exc),
        }
        print(json.dumps(error, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 2
    return 0


__all__ = ["CliError", "build_parser", "main"]
