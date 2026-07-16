"""Public development family for bounded workflow retry state machines.

The family models a deterministic workflow over an immutable event ledger.  It
tests retry cutoffs, branch selection, bounded revisits, and compensation while
keeping the observable claim deliberately extensional: the trusted code derives
the exact trace that a candidate must report, but does not claim that a
candidate really retried, waited, or traversed those states internally.

Two separately structured parsers and simulators must agree before a fixture is
admitted or an output is accepted.  This module runs no subprocess and grants
no candidate-execution, scoring, model-selection, or research-claim authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import os
from pathlib import PurePosixPath
import re
from typing import Final, Literal, TypeAlias

from .benchmark import NormalizedSemanticGraph, OperatorNode
from .executable_fixture_bundle import (
    EXECUTABLE_FIXTURE_BINDING_VERSION,
    EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION,
    OracleOutputRecord,
    compute_bound_fixture_sha256,
    compute_fixture_definition_semantic_sha256,
)
from .executable_fixture_profiles import (
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
    ExecutableFixtureProfile,
)
from .executable_static_types import (
    EXECUTABLE_STATIC_CONTRACT_VERSION,
    EXECUTABLE_STATIC_FAMILY_VERSION,
    EXECUTABLE_STATIC_SCHEMA_VERSION,
    METHOD_DEVELOPMENT_SPLIT,
    OpaqueFixtureDescriptor,
    domain_sha256,
    task_id_from_contract,
)
from .executable_workspace import (
    ExecutableWorkspaceError,
    ExpectedFile,
    FixtureDefinition,
    InputFile,
    InputSymlink,
    WorkspaceHandle,
    materialize_fixture,
    validate_expected_output_policy,
)


BOUNDED_RETRY_STATE_MACHINE_FAMILY_ID: Final[str] = (
    "bounded-retry-state-machine"
)
BOUNDED_RETRY_STATE_MACHINE_FILESYSTEM_IDENTITY: Final[str] = (
    "workflow-event-ledger"
)
BOUNDED_RETRY_STATE_MACHINE_OUTPUT_IDENTITY: Final[str] = (
    "terminal-state-and-attempt-report"
)
BOUNDED_RETRY_STATE_MACHINE_GENERATOR_VERSION: Final[str] = "1.0.0"
BOUNDED_RETRY_STATE_MACHINE_VERIFIER_IDENTITY: Final[str] = (
    "verify-bounded-retry-state-machine-v1"
)
BOUNDED_RETRY_STATE_MACHINE_ROOT: Final[PurePosixPath] = PurePosixPath(
    "input/workflow"
)
BOUNDED_RETRY_STATE_MACHINE_EVENTS: Final[str] = "input/workflow/events.tsv"
BOUNDED_RETRY_STATE_MACHINE_ATTEMPTS_OUTPUT: Final[str] = (
    "output/attempts.tsv"
)
BOUNDED_RETRY_STATE_MACHINE_TERMINAL_OUTPUT: Final[str] = (
    "output/terminal.tsv"
)
BOUNDED_RETRY_STATE_MACHINE_OUTPUT_MODE: Final[int] = 0o644
BOUNDED_RETRY_STATE_MACHINE_OUTPUT_MAXIMUM_BYTES: Final[int] = 64 * 1024
BOUNDED_RETRY_STATE_MACHINE_EVENT_LEDGER_MAXIMUM_BYTES: Final[int] = 32 * 1024
BOUNDED_RETRY_STATE_MACHINE_ALLOWED_TOOLS: Final[tuple[str, ...]] = (
    "awk",
    "mkdir",
    "sort",
)

# Honest final-state observability boundaries.
BOUNDED_RETRY_STATE_MACHINE_SYMLINK_DISTRACTORS_COVERED: Final[bool] = True
BOUNDED_RETRY_STATE_MACHINE_DIRECTORY_PERMISSION_ERRORS_COVERED: Final[
    bool
] = False
BOUNDED_RETRY_STATE_MACHINE_EFFECTIVE_ACCESS_FAILURES_COVERED: Final[
    bool
] = False
BOUNDED_RETRY_STATE_MACHINE_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE: Final[
    bool
] = True
BOUNDED_RETRY_STATE_MACHINE_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE: Final[
    bool
] = False
BOUNDED_RETRY_STATE_MACHINE_RETRY_HISTORY_OBSERVED: Final[bool] = False
BOUNDED_RETRY_STATE_MACHINE_TRANSITION_HISTORY_OBSERVED: Final[bool] = False
BOUNDED_RETRY_STATE_MACHINE_WAIT_HISTORY_OBSERVED: Final[bool] = False
BOUNDED_RETRY_STATE_MACHINE_TOOL_HISTORY_OBSERVED: Final[bool] = False
BOUNDED_RETRY_STATE_MACHINE_ATOMIC_PUBLICATION_HISTORY_OBSERVED: Final[
    bool
] = False
BOUNDED_RETRY_STATE_MACHINE_TRANSIENT_INPUT_PRESERVATION_OBSERVED: Final[
    bool
] = False
BOUNDED_RETRY_STATE_MACHINE_CANDIDATE_EXIT_STATUS_OBSERVED: Final[bool] = False

TransitionModel: TypeAlias = Literal[
    "linear",
    "branching",
    "cyclic-bounded",
    "compensating",
]
RetryPolicy: TypeAlias = Literal[
    "never",
    "fixed-two",
    "fixed-four",
    "until-terminal",
    "retry-transient-only",
]
EventOutcome: TypeAlias = Literal[
    "success",
    "transient-failure",
    "ordinary-failure",
    "terminal-failure",
]

BOUNDED_RETRY_STATE_MACHINE_TRANSITION_MODELS: Final[
    tuple[TransitionModel, ...]
] = (
    "linear",
    "branching",
    "cyclic-bounded",
    "compensating",
)
BOUNDED_RETRY_STATE_MACHINE_RETRY_POLICIES: Final[tuple[RetryPolicy, ...]] = (
    "never",
    "fixed-two",
    "fixed-four",
    "until-terminal",
    "retry-transient-only",
)

_OUTCOMES: Final[tuple[EventOutcome, ...]] = (
    "success",
    "transient-failure",
    "ordinary-failure",
    "terminal-failure",
)
_STATES: Final[dict[TransitionModel, tuple[str, ...]]] = {
    "linear": ("prepare", "execute", "publish"),
    "branching": ("choose", "fast", "safe", "publish"),
    "cyclic-bounded": ("check", "work"),
    "compensating": ("prepare", "apply", "publish", "compensate"),
}
_RETRY_CAPS: Final[dict[RetryPolicy, int]] = {
    "never": 1,
    "fixed-two": 2,
    "fixed-four": 4,
    "until-terminal": 6,
    "retry-transient-only": 6,
}
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(r"mds-[0-9a-f]{24}\Z")
_POSITIVE_INTEGER_RE: Final[re.Pattern[bytes]] = re.compile(
    rb"[1-9][0-9]{0,2}\Z"
)
_MAXIMUM_VISIT: Final[int] = 4
_MAXIMUM_ATTEMPT: Final[int] = 6
_MAXIMUM_EVENT_ROWS: Final[int] = 256


class BoundedRetryStateMachineError(ValueError):
    """Raised when a task, fixture, or state-machine report fails closed."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _closed_text(
    value: object, allowed: tuple[str, ...], field_name: str
) -> str:
    if type(value) is not str or value not in allowed:
        raise BoundedRetryStateMachineError(
            f"{field_name} is outside the closed family contract"
        )
    return value


@dataclass(frozen=True, slots=True)
class BoundedRetryStateMachineParameters:
    """One cell in the four-model by five-retry-policy grid."""

    transition_model: TransitionModel
    retry_policy: RetryPolicy

    def __post_init__(self) -> None:
        _closed_text(
            self.transition_model,
            BOUNDED_RETRY_STATE_MACHINE_TRANSITION_MODELS,
            "transition_model",
        )
        _closed_text(
            self.retry_policy,
            BOUNDED_RETRY_STATE_MACHINE_RETRY_POLICIES,
            "retry_policy",
        )

    def to_record(self) -> dict[str, str]:
        self.__post_init__()
        return {
            "parameter_type": BOUNDED_RETRY_STATE_MACHINE_FAMILY_ID,
            "transition_model": self.transition_model,
            "retry_policy": self.retry_policy,
        }


_MODEL_TEXT: Final[dict[TransitionModel, str]] = {
    "linear": (
        "Start at `prepare`, then on success visit `execute`, then `publish`; "
        "a successful publish completes the workflow.  Any failed visit "
        "terminates as failed."
    ),
    "branching": (
        "Start at `choose`.  Its successful event directive must be `fast` or "
        "`safe` and selects exactly that branch; never consume the other "
        "branch.  A successful selected branch visits `publish`, whose success "
        "completes the workflow.  Any failed visit terminates as failed."
    ),
    "cyclic-bounded": (
        "Start at `check`, whose successful directive is `next`, then visit "
        "`work`.  A successful work directive `repeat` returns to a fresh "
        "check/work visit and `finish` completes.  There are at most three work "
        "visits; `repeat` after the third terminates at `cycle-limit`.  Retry "
        "attempts do not increment the visit number."
    ),
    "compensating": (
        "Start at `prepare`, then `apply`, then `publish`; success completes.  A "
        "prepare failure terminates failed.  A final failure of apply or "
        "publish after successful prepare visits `compensate` once.  Successful "
        "compensation terminates compensated; failed compensation terminates "
        "compensation-failed."
    ),
}

_POLICY_TEXT: Final[dict[RetryPolicy, str]] = {
    "never": (
        "Use exactly one total attempt per state visit; every failure stops that "
        "visit with retry-disabled, except terminal-failure which is terminal."
    ),
    "fixed-two": (
        "Use at most two total attempts per state visit (not two retries), "
        "retrying transient and ordinary failure; terminal-failure stops."
    ),
    "fixed-four": (
        "Use at most four total attempts per state visit (not four retries), "
        "retrying transient and ordinary failure; terminal-failure stops."
    ),
    "until-terminal": (
        "Retry transient and ordinary failure until success or terminal-failure, "
        "with a hard ceiling of six total attempts per state visit."
    ),
    "retry-transient-only": (
        "Retry only transient-failure, with a hard ceiling of six total attempts "
        "per state visit; ordinary-failure and terminal-failure stop immediately."
    ),
}


def _task_contract(
    parameters: BoundedRetryStateMachineParameters,
) -> tuple[str, NormalizedSemanticGraph]:
    prompt = f"""Write one Bash program that operates only in the current workspace.

Read only `input/workflow/events.tsv`; ignore every other input path.  The file
is either empty or strict LF-terminated UTF-8 TSV and is at most 32768 bytes.
Each row has exactly STATE,
VISIT, ATTEMPT, OUTCOME, DIRECTIVE, DETAIL.  VISIT and ATTEMPT are canonical
positive decimals; VISIT is exactly 1 for linear, branching, and compensating
models and is from 1 through 4 for the cyclic model; ATTEMPT is at most 6.
Unreachable but model-valid cyclic visit-4 rows are unused decoys.  OUTCOME is one of
`success`, `transient-failure`, `ordinary-failure`, or `terminal-failure`.
DETAIL is nonempty strict UTF-8 without NUL, tab, or LF; no quoting or escaping
is interpreted.  Rows may appear in any physical order.  A repeated
STATE/VISIT/ATTEMPT key is valid only when the complete six-field row is byte
identical, in which case it denotes one event; conflicting duplicates are
invalid.  Look up and consume events only for the state visit and attempt that
the machine actually reaches.  A missing required event yields an incomplete
terminal instead of inventing an attempt.

This task uses transition model `{parameters.transition_model}`.  States are
{', '.join(_STATES[parameters.transition_model])}.  {_MODEL_TEXT[parameters.transition_model]}
Every successful event outside `choose` and `work` has directive `next`;
successful choose events use `fast` or `safe`; successful work events use
`repeat` or `finish`; every failure uses `-`.

This task uses retry policy `{parameters.retry_policy}`.  {_POLICY_TEXT[parameters.retry_policy]}
Success and terminal-failure always stop retrying.  Every retry budget resets
for each distinct (STATE, VISIT).

Write exact mode-0644 independent regular files with link count one.  For every
consumed attempt append one LF-terminated row to `output/attempts.tsv`:
`attempt`, sequence number starting at 1, STATE, VISIT, ATTEMPT, OUTCOME,
DIRECTIVE, DETAIL, and RESOLUTION (`retry`, `succeeded`, or `failed`).  If the
ledger is empty, this file is empty.  Write exactly one LF-terminated row to
`output/terminal.tsv`: `terminal`, TERMINAL, REASON, total consumed attempts,
CAUSE_STATE, CAUSE_VISIT, CAUSE_ATTEMPT, and CAUSE_OUTCOME.  The empty-ledger
row is exactly `terminal`, `empty`, `no-events`, `0`, `-`, `0`, `0`, `empty`.
RESOLUTION is `succeeded` for success, `retry` for a failure that the selected
policy will retry, and `failed` for the failure that stops a visit or initiates
compensation.  TERMINAL is exactly one of `empty`, `complete`, `failed`,
`incomplete`, `cycle-limit`, `compensated`, or `compensation-failed`.  REASON is
respectively selected from `no-events`, `workflow-complete`, `retry-disabled`,
`retry-budget-exhausted`, `nontransient-failure`, `terminal-failure`,
`event-ledger-exhausted`, `cycle-bound-exceeded`, `compensation-complete`, and
`compensation-failed` by the rules above.  A missing required event uses
TERMINAL `incomplete`, REASON `event-ledger-exhausted`, the requested
STATE/VISIT/ATTEMPT, and CAUSE_OUTCOME `missing`; it never initiates
compensation.  Otherwise failed terminals cite the stopping failure.  Complete
and cycle-limit terminals cite the last success.  A compensated terminal cites
the apply/publish failure that initiated compensation, while a
compensation-failed terminal cites the stopping compensation failure.  TOTAL is
the number of rows in attempts.tsv, including compensation attempts.
Leave a real mode-0755 `output/` directory and no other non-input path.  Preserve
every input path, kind, mode, byte, modification time, hard-link count, and
symlink target.  Use only Bash built-ins plus `awk`, `mkdir`, and `sort`.
"""
    graph = NormalizedSemanticGraph(
        nodes=(
            OperatorNode(
                "parse_workflow_event_ledger",
                ("path:input/workflow/events.tsv", "row-order:nonsemantic"),
            ),
            OperatorNode(
                "execute_bounded_state_visits",
                (
                    f"transition-model:{parameters.transition_model}",
                    f"retry-policy:{parameters.retry_policy}",
                    "attempt-hard-cap:6",
                    "budget-scope:state-visit",
                ),
            ),
            OperatorNode(
                "derive_terminal_state",
                ("cycle-work-visit-cap:3", "compensation-visits:at-most-one"),
            ),
            OperatorNode(
                "write_attempt_and_terminal_reports",
                (
                    "path:output/attempts.tsv",
                    "path:output/terminal.tsv",
                    "mode:0644",
                ),
            ),
        ),
        dependencies=((0, 1), (1, 2), (2, 3)),
    )
    return prompt, graph


def _validate_graph(graph: object) -> NormalizedSemanticGraph:
    if type(graph) is not NormalizedSemanticGraph:
        raise BoundedRetryStateMachineError("graph has the wrong exact type")
    if type(graph.nodes) is not tuple or not graph.nodes:
        raise BoundedRetryStateMachineError("graph nodes are invalid")
    if type(graph.dependencies) is not tuple:
        raise BoundedRetryStateMachineError("graph dependencies are invalid")
    for node in graph.nodes:
        if (
            type(node) is not OperatorNode
            or type(node.name) is not str
            or not node.name
            or "\0" in node.name
            or type(node.parameters) is not tuple
            or any(type(item) is not str for item in node.parameters)
        ):
            raise BoundedRetryStateMachineError("graph node is noncanonical")
    for edge in graph.dependencies:
        if (
            type(edge) is not tuple
            or len(edge) != 2
            or any(type(index) is not int for index in edge)
        ):
            raise BoundedRetryStateMachineError("graph edge is noncanonical")
        source, target = edge
        if source < 0 or source >= target or target >= len(graph.nodes):
            raise BoundedRetryStateMachineError("graph edge order is invalid")
    rebuilt = NormalizedSemanticGraph(
        nodes=tuple(
            OperatorNode(node.name, node.parameters) for node in graph.nodes
        ),
        dependencies=graph.dependencies,
    )
    if rebuilt != graph:
        raise BoundedRetryStateMachineError("graph reconstruction changed")
    return graph


def bounded_retry_state_machine_task_semantic_core(
    parameters: BoundedRetryStateMachineParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> dict[str, object]:
    if type(parameters) is not BoundedRetryStateMachineParameters:
        raise BoundedRetryStateMachineError("parameters have the wrong type")
    parameters.__post_init__()
    if type(prompt) is not str or not prompt.strip() or "\0" in prompt:
        raise BoundedRetryStateMachineError("prompt is invalid")
    _validate_graph(graph)
    expected_prompt, expected_graph = _task_contract(parameters)
    if prompt != expected_prompt or graph != expected_graph:
        raise BoundedRetryStateMachineError("prompt or graph differs")
    return {
        "schema_version": EXECUTABLE_STATIC_SCHEMA_VERSION,
        "contract_version": EXECUTABLE_STATIC_CONTRACT_VERSION,
        "split_role": METHOD_DEVELOPMENT_SPLIT,
        "family_id": BOUNDED_RETRY_STATE_MACHINE_FAMILY_ID,
        "family_version": EXECUTABLE_STATIC_FAMILY_VERSION,
        "parameters": parameters.to_record(),
        "prompt": prompt,
        "graph": graph.to_record(),
        "graph_sha256": graph.hash,
        "filesystem_identity": BOUNDED_RETRY_STATE_MACHINE_FILESYSTEM_IDENTITY,
        "output_identity": BOUNDED_RETRY_STATE_MACHINE_OUTPUT_IDENTITY,
        "allowed_tools": list(BOUNDED_RETRY_STATE_MACHINE_ALLOWED_TOOLS),
        "public": True,
        "sealed": False,
        "candidate_execution_authorized": False,
        "model_selection_eligible": False,
        "claim_authorized": False,
    }


def compute_bounded_retry_state_machine_task_sha256(
    parameters: BoundedRetryStateMachineParameters,
    prompt: str,
    graph: NormalizedSemanticGraph,
) -> str:
    return domain_sha256(
        "cbds.executable-static.task-contract.v1",
        bounded_retry_state_machine_task_semantic_core(
            parameters, prompt, graph
        ),
    )


@dataclass(frozen=True, slots=True)
class BoundedRetryStateMachineTask:
    task_id: str
    parameters: BoundedRetryStateMachineParameters
    prompt: str
    graph: NormalizedSemanticGraph
    fixtures: tuple[OpaqueFixtureDescriptor, ...]
    task_contract_sha256: str
    family_id: str = BOUNDED_RETRY_STATE_MACHINE_FAMILY_ID
    family_version: str = EXECUTABLE_STATIC_FAMILY_VERSION
    filesystem_identity: str = BOUNDED_RETRY_STATE_MACHINE_FILESYSTEM_IDENTITY
    output_identity: str = BOUNDED_RETRY_STATE_MACHINE_OUTPUT_IDENTITY
    allowed_tools: tuple[str, ...] = BOUNDED_RETRY_STATE_MACHINE_ALLOWED_TOOLS
    split_role: str = METHOD_DEVELOPMENT_SPLIT
    public: bool = True
    sealed: bool = False
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.parameters) is not BoundedRetryStateMachineParameters
            or self.family_id != BOUNDED_RETRY_STATE_MACHINE_FAMILY_ID
            or type(self.family_id) is not str
            or self.family_version != EXECUTABLE_STATIC_FAMILY_VERSION
            or type(self.family_version) is not str
            or self.filesystem_identity
            != BOUNDED_RETRY_STATE_MACHINE_FILESYSTEM_IDENTITY
            or type(self.filesystem_identity) is not str
            or self.output_identity != BOUNDED_RETRY_STATE_MACHINE_OUTPUT_IDENTITY
            or type(self.output_identity) is not str
            or type(self.allowed_tools) is not tuple
            or self.allowed_tools != BOUNDED_RETRY_STATE_MACHINE_ALLOWED_TOOLS
            or any(type(tool) is not str for tool in self.allowed_tools)
            or self.split_role != METHOD_DEVELOPMENT_SPLIT
            or type(self.split_role) is not str
            or self.public is not True
            or self.sealed is not False
            or self.candidate_execution_authorized is not False
            or self.model_selection_eligible is not False
            or self.claim_authorized is not False
        ):
            raise BoundedRetryStateMachineError("task metadata is invalid")
        expected = compute_bounded_retry_state_machine_task_sha256(
            self.parameters, self.prompt, self.graph
        )
        if (
            type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or not _is_sha256(self.task_contract_sha256)
            or self.task_contract_sha256 != expected
            or self.task_id != task_id_from_contract(expected)
        ):
            raise BoundedRetryStateMachineError("task identity is invalid")
        if (
            type(self.fixtures) is not tuple
            or len(self.fixtures) != len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES)
            or any(
                type(item) is not OpaqueFixtureDescriptor
                for item in self.fixtures
            )
        ):
            raise BoundedRetryStateMachineError("task descriptors are invalid")
        for descriptor in self.fixtures:
            descriptor.__post_init__()
        if (
            len({item.fixture_id for item in self.fixtures}) != 5
            or any(
                item.task_contract_sha256 != expected
                for item in self.fixtures
            )
        ):
            raise BoundedRetryStateMachineError("descriptor binding is invalid")

    @property
    def graph_sha256(self) -> str:
        self.__post_init__()
        return self.graph.hash

    def to_public_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            **bounded_retry_state_machine_task_semantic_core(
                self.parameters, self.prompt, self.graph
            ),
            "task_id": self.task_id,
            "task_contract_sha256": self.task_contract_sha256,
            "fixtures": [item.to_public_record() for item in self.fixtures],
        }


def _bootstrap_descriptors(
    task_contract_sha256: str,
) -> tuple[OpaqueFixtureDescriptor, ...]:
    return tuple(
        OpaqueFixtureDescriptor(
            fixture_id=f"fx-{digest[:24]}",
            fixture_sha256=digest,
            task_contract_sha256=task_contract_sha256,
        )
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
        for digest in (
            domain_sha256(
                "cbds.executable-static.fixture.v1",
                {
                    "task_contract_sha256": task_contract_sha256,
                    "profile_sha256": profile.profile_sha256,
                },
            ),
        )
    )


def _bootstrap_task(
    parameters: BoundedRetryStateMachineParameters,
) -> BoundedRetryStateMachineTask:
    prompt, graph = _task_contract(parameters)
    digest = compute_bounded_retry_state_machine_task_sha256(
        parameters, prompt, graph
    )
    return BoundedRetryStateMachineTask(
        task_id=task_id_from_contract(digest),
        parameters=parameters,
        prompt=prompt,
        graph=graph,
        fixtures=_bootstrap_descriptors(digest),
        task_contract_sha256=digest,
    )


def build_bounded_retry_state_machine_tasks() -> tuple[
    BoundedRetryStateMachineTask, ...
]:
    tasks: list[BoundedRetryStateMachineTask] = []
    for model in BOUNDED_RETRY_STATE_MACHINE_TRANSITION_MODELS:
        for policy in BOUNDED_RETRY_STATE_MACHINE_RETRY_POLICIES:
            bootstrap = _bootstrap_task(
                BoundedRetryStateMachineParameters(model, policy)
            )
            descriptors = tuple(
                _construct_bounded_retry_state_machine_fixture_bundle(
                    bootstrap, profile
                ).descriptor
                for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
            )
            tasks.append(replace(bootstrap, fixtures=descriptors))
    selected = tuple(tasks)
    if (
        len(selected) != 20
        or len({task.task_id for task in selected}) != 20
        or len({task.task_contract_sha256 for task in selected}) != 20
        or len({task.graph_sha256 for task in selected}) != 20
    ):
        raise BoundedRetryStateMachineError("task grid is not 20 unique tasks")
    return selected


@dataclass(frozen=True, slots=True)
class _Event:
    state: str
    visit: int
    attempt: int
    outcome: EventOutcome
    directive: str
    detail: str

    def key(self) -> tuple[str, int, int]:
        return self.state, self.visit, self.attempt


def _event_row(event: _Event) -> bytes:
    return (
        f"{event.state}\t{event.visit}\t{event.attempt}\t{event.outcome}\t"
        f"{event.directive}\t{event.detail}\n"
    ).encode("utf-8")


def _profile_outcomes(profile_id: str) -> tuple[EventOutcome, ...]:
    if profile_id == "spaces-unicode":
        return (
            "transient-failure",
            "transient-failure",
            "success",
            "ordinary-failure",
            "success",
            "success",
        )
    if profile_id == "leading-dashes-globs":
        return (
            "ordinary-failure",
            "success",
            "transient-failure",
            "success",
            "success",
            "success",
        )
    if profile_id == "empty-duplicates":
        return ("success",) * 6
    if profile_id == "symlinks-ordering":
        return (
            "transient-failure",
            "transient-failure",
            "transient-failure",
            "transient-failure",
            "transient-failure",
            "success",
        )
    if profile_id == "partial-permissions":
        return (
            "success",
            "terminal-failure",
            "success",
            "success",
            "success",
            "success",
        )
    raise BoundedRetryStateMachineError("unsupported fixture profile")


def _event_directive(
    model: TransitionModel,
    state: str,
    visit: int,
    outcome: EventOutcome,
    profile_id: str,
) -> str:
    if outcome != "success":
        return "-"
    if model == "branching" and state == "choose":
        return "fast" if profile_id in {"spaces-unicode", "empty-duplicates"} else "safe"
    if model == "cyclic-bounded" and state == "work":
        if visit < 3:
            return "repeat"
        return "repeat" if profile_id == "leading-dashes-globs" else "finish"
    return "next"


def _event_detail(profile_id: str, state: str, visit: int, attempt: int) -> str:
    if profile_id == "spaces-unicode":
        return f"café 雪 state {state} visit {visit} attempt {attempt}"
    if profile_id == "leading-dashes-globs":
        return f"-[*]? {state} v{visit} a{attempt}"
    if profile_id == "empty-duplicates":
        return "duplicate payload"
    if profile_id == "symlinks-ordering":
        return f"reverse order {state} {visit} {attempt}"
    if profile_id == "partial-permissions":
        return f"mode 0400 {state} {visit} {attempt}"
    raise BoundedRetryStateMachineError("unsupported detail profile")


def _profile_events(
    profile: ExecutableFixtureProfile,
    model: TransitionModel,
) -> bytes:
    if profile.profile_id == "empty-duplicates" and model == "linear":
        return b""
    outcomes = _profile_outcomes(profile.profile_id)
    rows: list[bytes] = []
    for state in _STATES[model]:
        maximum_visit = 4 if model == "cyclic-bounded" else 1
        for visit in range(1, maximum_visit + 1):
            for attempt, base_outcome in enumerate(outcomes, start=1):
                outcome = base_outcome
                # The permission profile reaches the first state, then records
                # an immediate terminal failure in the next forward state.
                if profile.profile_id == "partial-permissions":
                    first = _STATES[model][0]
                    if state == first:
                        outcome = "success"
                    elif model == "compensating" and state == "compensate":
                        outcome = "success"
                    elif attempt == 1:
                        outcome = "terminal-failure"
                    else:
                        outcome = "success"
                event = _Event(
                    state=state,
                    visit=visit,
                    attempt=attempt,
                    outcome=outcome,
                    directive=_event_directive(
                        model, state, visit, outcome, profile.profile_id
                    ),
                    detail=_event_detail(
                        profile.profile_id, state, visit, attempt
                    ),
                )
                row = _event_row(event)
                rows.append(row)
                if profile.profile_id == "empty-duplicates":
                    rows.append(row)
    if profile.profile_id == "symlinks-ordering":
        rows.reverse()
    elif profile.profile_id == "leading-dashes-globs" and rows:
        rows = rows[3:] + rows[:3]
    return b"".join(rows)


def _fixture_inputs(
    profile: ExecutableFixtureProfile,
    model: TransitionModel,
) -> tuple[InputFile | InputSymlink, ...]:
    mode = 0o400 if profile.profile_id == "partial-permissions" else 0o600
    inputs: list[InputFile | InputSymlink] = [
        InputFile(
            BOUNDED_RETRY_STATE_MACHINE_EVENTS,
            _profile_events(profile, model),
            mode,
        )
    ]
    if profile.profile_id == "spaces-unicode":
        inputs.append(InputFile("input/workflow/ignore café 雪.txt", b"ignore\n"))
    elif profile.profile_id == "leading-dashes-globs":
        inputs.append(InputFile("input/workflow/-ignore[*]?.txt", b"ignore\n"))
    elif profile.profile_id == "empty-duplicates":
        inputs.append(InputFile("input/workflow/empty-note.txt", b""))
    elif profile.profile_id == "symlinks-ordering":
        inputs.extend(
            (
                InputSymlink("input/workflow/events-link.tsv", "events.tsv"),
                InputSymlink("input/workflow/dangling[*].tsv", "missing.tsv"),
            )
        )
    elif profile.profile_id == "partial-permissions":
        inputs.extend(
            (
                InputFile("input/workflow/unlisted-denied.tsv", b"ignore\n", 0o000),
                InputSymlink("input/workflow/unlisted-link.tsv", "events.tsv"),
            )
        )
    return tuple(inputs)


def _revalidate_definition(definition: object) -> FixtureDefinition:
    if type(definition) is not FixtureDefinition:
        raise BoundedRetryStateMachineError("definition has the wrong exact type")
    try:
        definition.__post_init__()
        rebuilt_inputs: list[InputFile | InputSymlink] = []
        for item in definition.inputs:
            if type(item) is InputFile:
                rebuilt_inputs.append(InputFile(item.path, item.content, item.mode))
            elif type(item) is InputSymlink:
                rebuilt_inputs.append(InputSymlink(item.path, item.target))
            else:
                raise BoundedRetryStateMachineError("input has the wrong exact type")
        rebuilt = FixtureDefinition(
            fixture_id=definition.fixture_id,
            inputs=tuple(rebuilt_inputs),
            expected_files=tuple(
                ExpectedFile(item.path, item.maximum_bytes, item.mode)
                for item in definition.expected_files
            ),
            schema_version=definition.schema_version,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc, BoundedRetryStateMachineError):
            raise
        raise BoundedRetryStateMachineError("definition revalidation failed") from exc
    if rebuilt != definition:
        raise BoundedRetryStateMachineError("definition changed on reconstruction")
    return definition


def _events_bytes(definition: FixtureDefinition) -> bytes:
    checked = _revalidate_definition(definition)
    matches = tuple(
        item
        for item in checked.inputs
        if item.path == BOUNDED_RETRY_STATE_MACHINE_EVENTS
    )
    if len(matches) != 1 or type(matches[0]) is not InputFile:
        raise BoundedRetryStateMachineError("event ledger is missing or not regular")
    content = matches[0].content
    if len(content) > BOUNDED_RETRY_STATE_MACHINE_EVENT_LEDGER_MAXIMUM_BYTES:
        raise BoundedRetryStateMachineError("event ledger exceeds its family ceiling")
    return content


def _decode_ascii(raw: bytes, label: str) -> str:
    try:
        return raw.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise BoundedRetryStateMachineError(f"{label} is not ASCII") from exc


def _decode_detail(raw: bytes) -> str:
    if not raw or b"\0" in raw or b"\t" in raw or b"\n" in raw:
        raise BoundedRetryStateMachineError("event detail is invalid")
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise BoundedRetryStateMachineError("event detail is not UTF-8") from exc


def _canonical_positive(raw: bytes, label: str, maximum: int) -> int:
    if _POSITIVE_INTEGER_RE.fullmatch(raw) is None:
        raise BoundedRetryStateMachineError(f"{label} is not canonical")
    value = int(raw)
    if value > maximum:
        raise BoundedRetryStateMachineError(f"{label} exceeds its bound")
    return value


def _validate_event_for_model(
    event: _Event, model: TransitionModel
) -> _Event:
    if type(event) is not _Event:
        raise BoundedRetryStateMachineError("event has the wrong exact type")
    if event.state not in _STATES[model]:
        raise BoundedRetryStateMachineError("event state is outside the model")
    maximum_visit = 4 if model == "cyclic-bounded" else 1
    if (
        type(event.visit) is not int
        or event.visit < 1
        or event.visit > maximum_visit
        or type(event.attempt) is not int
        or event.attempt < 1
        or event.attempt > _MAXIMUM_ATTEMPT
        or type(event.outcome) is not str
        or event.outcome not in _OUTCOMES
        or type(event.directive) is not str
        or type(event.detail) is not str
        or not event.detail
        or any(character in event.detail for character in ("\0", "\t", "\n"))
    ):
        raise BoundedRetryStateMachineError("event fields are invalid")
    if event.outcome != "success":
        if event.directive != "-":
            raise BoundedRetryStateMachineError("failure directive must be dash")
    elif model == "branching" and event.state == "choose":
        if event.directive not in {"fast", "safe"}:
            raise BoundedRetryStateMachineError("branch directive is invalid")
    elif model == "cyclic-bounded" and event.state == "work":
        if event.directive not in {"repeat", "finish"}:
            raise BoundedRetryStateMachineError("work directive is invalid")
    elif event.directive != "next":
        raise BoundedRetryStateMachineError("success directive must be next")
    return event


def _primary_parse_events(
    definition: FixtureDefinition,
    model: TransitionModel,
) -> dict[tuple[str, int, int], _Event]:
    content = _events_bytes(definition)
    if not content:
        return {}
    if not content.endswith(b"\n"):
        raise BoundedRetryStateMachineError("event ledger is not LF terminated")
    raw_rows = content[:-1].split(b"\n")
    if not raw_rows or len(raw_rows) > _MAXIMUM_EVENT_ROWS:
        raise BoundedRetryStateMachineError("event row count is invalid")
    result: dict[tuple[str, int, int], _Event] = {}
    raw_by_key: dict[tuple[str, int, int], bytes] = {}
    for raw_row in raw_rows:
        fields = raw_row.split(b"\t")
        if len(fields) != 6:
            raise BoundedRetryStateMachineError("event row field count is invalid")
        state = _decode_ascii(fields[0], "state")
        visit = _canonical_positive(fields[1], "visit", _MAXIMUM_VISIT)
        attempt = _canonical_positive(fields[2], "attempt", _MAXIMUM_ATTEMPT)
        outcome = _decode_ascii(fields[3], "outcome")
        directive = _decode_ascii(fields[4], "directive")
        detail = _decode_detail(fields[5])
        if outcome not in _OUTCOMES:
            raise BoundedRetryStateMachineError("event outcome is invalid")
        event = _validate_event_for_model(
            _Event(state, visit, attempt, outcome, directive, detail),  # type: ignore[arg-type]
            model,
        )
        key = event.key()
        if key in result:
            if raw_by_key[key] != raw_row or result[key] != event:
                raise BoundedRetryStateMachineError("duplicate event key conflicts")
            continue
        result[key] = event
        raw_by_key[key] = raw_row
    return result


def _reference_events_bytes(definition: FixtureDefinition) -> bytes:
    checked = _revalidate_definition(definition)
    selected: InputFile | None = None
    for item in checked.inputs:
        if item.path != BOUNDED_RETRY_STATE_MACHINE_EVENTS:
            continue
        if selected is not None or type(item) is not InputFile:
            raise BoundedRetryStateMachineError(
                "reference event ledger is not one exact regular file"
            )
        selected = item
    if selected is None:
        raise BoundedRetryStateMachineError("reference event ledger is absent")
    if len(selected.content) > BOUNDED_RETRY_STATE_MACHINE_EVENT_LEDGER_MAXIMUM_BYTES:
        raise BoundedRetryStateMachineError("reference event ledger exceeds ceiling")
    return selected.content


def _reference_validate_event(event: _Event, model: TransitionModel) -> _Event:
    if type(event) is not _Event:
        raise BoundedRetryStateMachineError("reference event type is invalid")
    states = {
        "linear": {"prepare", "execute", "publish"},
        "branching": {"choose", "fast", "safe", "publish"},
        "cyclic-bounded": {"check", "work"},
        "compensating": {"prepare", "apply", "publish", "compensate"},
    }[model]
    visit_maximum = 4 if model == "cyclic-bounded" else 1
    if (
        event.state not in states
        or type(event.visit) is not int
        or not 1 <= event.visit <= visit_maximum
        or type(event.attempt) is not int
        or not 1 <= event.attempt <= 6
        or event.outcome
        not in {
            "success",
            "transient-failure",
            "ordinary-failure",
            "terminal-failure",
        }
        or type(event.detail) is not str
        or not event.detail
        or "\0" in event.detail
        or "\t" in event.detail
        or "\n" in event.detail
    ):
        raise BoundedRetryStateMachineError("reference event semantics are invalid")
    if event.outcome != "success" and event.directive != "-":
        raise BoundedRetryStateMachineError("reference failure route is invalid")
    if event.outcome == "success":
        allowed = {"next"}
        if model == "branching" and event.state == "choose":
            allowed = {"fast", "safe"}
        elif model == "cyclic-bounded" and event.state == "work":
            allowed = {"repeat", "finish"}
        if event.directive not in allowed:
            raise BoundedRetryStateMachineError("reference success route is invalid")
    return event


def _reference_parse_events(
    definition: FixtureDefinition,
    model: TransitionModel,
) -> tuple[_Event, ...]:
    data = _reference_events_bytes(definition)
    if data == b"":
        return ()
    if data[-1:] != b"\n":
        raise BoundedRetryStateMachineError("reference ledger lacks final LF")
    pieces = data.split(b"\n")
    if pieces[-1] != b"" or not pieces[:-1] or len(pieces) - 1 > _MAXIMUM_EVENT_ROWS:
        raise BoundedRetryStateMachineError("reference row envelope is invalid")
    unique: dict[tuple[str, int, int], tuple[bytes, _Event]] = {}
    for row in pieces[:-1]:
        columns = row.split(b"\t")
        if len(columns) != 6:
            raise BoundedRetryStateMachineError("reference field count differs")
        try:
            state = columns[0].decode("ascii", errors="strict")
            visit_text = columns[1].decode("ascii", errors="strict")
            attempt_text = columns[2].decode("ascii", errors="strict")
            outcome = columns[3].decode("ascii", errors="strict")
            directive = columns[4].decode("ascii", errors="strict")
            detail = columns[5].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise BoundedRetryStateMachineError("reference decoding failed") from exc
        if (
            not re.fullmatch(r"[1-9][0-9]{0,2}", visit_text)
            or not re.fullmatch(r"[1-9][0-9]{0,2}", attempt_text)
        ):
            raise BoundedRetryStateMachineError("reference ordinal is noncanonical")
        visit = int(visit_text)
        attempt = int(attempt_text)
        if visit > _MAXIMUM_VISIT or attempt > _MAXIMUM_ATTEMPT:
            raise BoundedRetryStateMachineError("reference ordinal exceeds bound")
        if (
            not detail
            or "\0" in detail
            or "\t" in detail
            or "\n" in detail
            or outcome not in _OUTCOMES
        ):
            raise BoundedRetryStateMachineError("reference event field is invalid")
        event = _reference_validate_event(
            _Event(state, visit, attempt, outcome, directive, detail),  # type: ignore[arg-type]
            model,
        )
        key = event.key()
        previous = unique.get(key)
        if previous is not None and previous != (row, event):
            raise BoundedRetryStateMachineError("reference duplicate conflicts")
        unique[key] = (row, event)
    return tuple(
        pair[1]
        for _, pair in sorted(
            unique.items(), key=lambda item: (item[0][0].encode("ascii"), item[0][1], item[0][2])
        )
    )


@dataclass(frozen=True, slots=True)
class _AttemptObservation:
    sequence: int
    event: _Event
    resolution: str


@dataclass(frozen=True, slots=True)
class _TerminalObservation:
    terminal: str
    reason: str
    total: int
    cause_state: str
    cause_visit: int
    cause_attempt: int
    cause_outcome: str


@dataclass(frozen=True, slots=True)
class BoundedRetryStateMachineOutput:
    attempts: bytes
    terminal: bytes

    def __post_init__(self) -> None:
        if (
            type(self.attempts) is not bytes
            or type(self.terminal) is not bytes
            or len(self.attempts) > BOUNDED_RETRY_STATE_MACHINE_OUTPUT_MAXIMUM_BYTES
            or len(self.terminal) > BOUNDED_RETRY_STATE_MACHINE_OUTPUT_MAXIMUM_BYTES
            or not self.terminal.endswith(b"\n")
            or (self.attempts and not self.attempts.endswith(b"\n"))
        ):
            raise BoundedRetryStateMachineError("output byte envelope is invalid")


def _attempts_bytes(observations: tuple[_AttemptObservation, ...]) -> bytes:
    rows: list[bytes] = []
    for observation in observations:
        event = observation.event
        rows.append(
            (
                f"attempt\t{observation.sequence}\t{event.state}\t{event.visit}\t"
                f"{event.attempt}\t{event.outcome}\t{event.directive}\t"
                f"{event.detail}\t{observation.resolution}\n"
            ).encode("utf-8")
        )
    return b"".join(rows)


def _terminal_bytes(observation: _TerminalObservation) -> bytes:
    return (
        f"terminal\t{observation.terminal}\t{observation.reason}\t"
        f"{observation.total}\t{observation.cause_state}\t"
        f"{observation.cause_visit}\t{observation.cause_attempt}\t"
        f"{observation.cause_outcome}\n"
    ).encode("utf-8")


def _empty_terminal() -> _TerminalObservation:
    return _TerminalObservation("empty", "no-events", 0, "-", 0, 0, "empty")


def _failure_reason(policy: RetryPolicy, event: _Event, attempt: int) -> str:
    if event.outcome == "terminal-failure":
        return "terminal-failure"
    if policy == "never":
        return "retry-disabled"
    if policy == "retry-transient-only" and event.outcome == "ordinary-failure":
        return "nontransient-failure"
    if attempt >= _RETRY_CAPS[policy]:
        return "retry-budget-exhausted"
    raise BoundedRetryStateMachineError("failure reason requested before stop")


def _should_retry(policy: RetryPolicy, event: _Event, attempt: int) -> bool:
    if event.outcome in {"success", "terminal-failure"}:
        return False
    if attempt >= _RETRY_CAPS[policy] or policy == "never":
        return False
    if policy == "retry-transient-only":
        return event.outcome == "transient-failure"
    return True


def _primary_run_visit(
    events: dict[tuple[str, int, int], _Event],
    policy: RetryPolicy,
    state: str,
    visit: int,
    observations: list[_AttemptObservation],
) -> tuple[bool, _Event | None, str]:
    for attempt in range(1, _RETRY_CAPS[policy] + 1):
        event = events.get((state, visit, attempt))
        if event is None:
            return False, None, "event-ledger-exhausted"
        if event.outcome == "success":
            observations.append(
                _AttemptObservation(len(observations) + 1, event, "succeeded")
            )
            return True, event, "success"
        if _should_retry(policy, event, attempt):
            observations.append(
                _AttemptObservation(len(observations) + 1, event, "retry")
            )
            continue
        observations.append(
            _AttemptObservation(len(observations) + 1, event, "failed")
        )
        return False, event, _failure_reason(policy, event, attempt)
    raise BoundedRetryStateMachineError("retry loop escaped its fixed cap")


def _terminal_from_failure(
    observations: list[_AttemptObservation],
    state: str,
    visit: int,
    event: _Event | None,
    reason: str,
    *,
    terminal: str = "failed",
) -> _TerminalObservation:
    if event is None:
        return _TerminalObservation(
            "incomplete",
            reason,
            len(observations),
            state,
            visit,
            1 if not observations or observations[-1].event.state != state or observations[-1].event.visit != visit else observations[-1].event.attempt + 1,
            "missing",
        )
    return _TerminalObservation(
        terminal,
        reason,
        len(observations),
        event.state,
        event.visit,
        event.attempt,
        event.outcome,
    )


def _terminal_from_success(
    observations: list[_AttemptObservation], terminal: str, reason: str
) -> _TerminalObservation:
    event = observations[-1].event
    return _TerminalObservation(
        terminal,
        reason,
        len(observations),
        event.state,
        event.visit,
        event.attempt,
        event.outcome,
    )


def _terminal_from_event(
    observations: list[_AttemptObservation],
    terminal: str,
    reason: str,
    event: _Event,
) -> _TerminalObservation:
    return _TerminalObservation(
        terminal,
        reason,
        len(observations),
        event.state,
        event.visit,
        event.attempt,
        event.outcome,
    )


def _primary_simulate(
    events: dict[tuple[str, int, int], _Event],
    parameters: BoundedRetryStateMachineParameters,
) -> tuple[tuple[_AttemptObservation, ...], _TerminalObservation]:
    if not events:
        return (), _empty_terminal()
    observations: list[_AttemptObservation] = []
    visits: dict[str, int] = {}
    model = parameters.transition_model
    compensation_cause: _Event | None = None
    state = {
        "linear": "prepare",
        "branching": "choose",
        "cyclic-bounded": "check",
        "compensating": "prepare",
    }[model]
    for _ in range(64):
        visits[state] = visits.get(state, 0) + 1
        visit = visits[state]
        succeeded, event, reason = _primary_run_visit(
            events, parameters.retry_policy, state, visit, observations
        )
        if not succeeded:
            if model == "compensating" and state in {"apply", "publish"}:
                if event is None:
                    return tuple(observations), _terminal_from_failure(
                        observations, state, visit, event, reason
                    )
                compensation_cause = event
                state = "compensate"
                continue
            terminal = "compensation-failed" if state == "compensate" else "failed"
            terminal_reason = (
                reason
                if state != "compensate" or event is None
                else "compensation-failed"
            )
            return tuple(observations), _terminal_from_failure(
                observations, state, visit, event, terminal_reason, terminal=terminal
            )
        if event is None:
            raise BoundedRetryStateMachineError("successful visit lacks an event")
        if model == "linear":
            if state == "prepare":
                state = "execute"
            elif state == "execute":
                state = "publish"
            else:
                return tuple(observations), _terminal_from_success(
                    observations, "complete", "workflow-complete"
                )
        elif model == "branching":
            if state == "choose":
                state = event.directive
            elif state in {"fast", "safe"}:
                state = "publish"
            else:
                return tuple(observations), _terminal_from_success(
                    observations, "complete", "workflow-complete"
                )
        elif model == "cyclic-bounded":
            if state == "check":
                state = "work"
            elif event.directive == "finish":
                return tuple(observations), _terminal_from_success(
                    observations, "complete", "workflow-complete"
                )
            elif visit >= 3:
                return tuple(observations), _terminal_from_success(
                    observations, "cycle-limit", "cycle-bound-exceeded"
                )
            else:
                state = "check"
        else:
            if state == "prepare":
                state = "apply"
            elif state == "apply":
                state = "publish"
            elif state == "publish":
                return tuple(observations), _terminal_from_success(
                    observations, "complete", "workflow-complete"
                )
            else:
                if compensation_cause is None:
                    raise BoundedRetryStateMachineError(
                        "compensation lacks an initiating failure"
                    )
                return tuple(observations), _terminal_from_event(
                    observations,
                    "compensated",
                    "compensation-complete",
                    compensation_cause,
                )
    raise BoundedRetryStateMachineError("state machine exceeded its structural bound")


def _reference_lookup(
    events: tuple[_Event, ...], state: str, visit: int, attempt: int
) -> _Event | None:
    matches = tuple(
        event
        for event in events
        if event.state == state
        and event.visit == visit
        and event.attempt == attempt
    )
    if len(matches) > 1:
        raise BoundedRetryStateMachineError("reference lookup is ambiguous")
    return None if not matches else matches[0]


def _reference_run_visit(
    events: tuple[_Event, ...],
    policy: RetryPolicy,
    state: str,
    visit: int,
    observations: list[_AttemptObservation],
) -> tuple[str, _Event | None, str]:
    limit = 1
    if policy == "fixed-two":
        limit = 2
    elif policy == "fixed-four":
        limit = 4
    elif policy in {"until-terminal", "retry-transient-only"}:
        limit = 6
    attempt = 1
    while attempt <= limit:
        event = _reference_lookup(events, state, visit, attempt)
        if event is None:
            return "missing", None, "event-ledger-exhausted"
        if event.outcome == "success":
            observations.append(
                _AttemptObservation(len(observations) + 1, event, "succeeded")
            )
            return "success", event, "success"
        terminal = event.outcome == "terminal-failure"
        retryable_kind = event.outcome in {
            "transient-failure",
            "ordinary-failure",
        }
        if policy == "retry-transient-only":
            retryable_kind = event.outcome == "transient-failure"
        retry = (
            policy != "never"
            and retryable_kind
            and not terminal
            and attempt < limit
        )
        if retry:
            observations.append(
                _AttemptObservation(len(observations) + 1, event, "retry")
            )
            attempt += 1
            continue
        observations.append(
            _AttemptObservation(len(observations) + 1, event, "failed")
        )
        if terminal:
            reason = "terminal-failure"
        elif policy == "never":
            reason = "retry-disabled"
        elif policy == "retry-transient-only" and event.outcome == "ordinary-failure":
            reason = "nontransient-failure"
        else:
            reason = "retry-budget-exhausted"
        return "failure", event, reason
    raise BoundedRetryStateMachineError("reference visit exceeded cap")


def _reference_empty_terminal() -> _TerminalObservation:
    return _TerminalObservation(
        terminal="empty",
        reason="no-events",
        total=0,
        cause_state="-",
        cause_visit=0,
        cause_attempt=0,
        cause_outcome="empty",
    )


def _reference_failure_terminal(
    observations: list[_AttemptObservation],
    state: str,
    visit: int,
    event: _Event | None,
    reason: str,
    terminal: str = "failed",
) -> _TerminalObservation:
    if event is None:
        next_attempt = 1
        if observations:
            last = observations[-1].event
            if last.state == state and last.visit == visit:
                next_attempt = last.attempt + 1
        return _TerminalObservation(
            "incomplete",
            reason,
            len(observations),
            state,
            visit,
            next_attempt,
            "missing",
        )
    return _TerminalObservation(
        terminal,
        reason,
        len(observations),
        event.state,
        event.visit,
        event.attempt,
        event.outcome,
    )


def _reference_success_terminal(
    observations: list[_AttemptObservation], terminal: str, reason: str
) -> _TerminalObservation:
    if not observations or observations[-1].event.outcome != "success":
        raise BoundedRetryStateMachineError("reference success cause is invalid")
    event = observations[-1].event
    return _TerminalObservation(
        terminal,
        reason,
        len(observations),
        event.state,
        event.visit,
        event.attempt,
        "success",
    )


def _reference_event_terminal(
    observations: list[_AttemptObservation],
    terminal: str,
    reason: str,
    event: _Event,
) -> _TerminalObservation:
    return _TerminalObservation(
        terminal,
        reason,
        len(observations),
        event.state,
        event.visit,
        event.attempt,
        event.outcome,
    )


def _reference_attempts_bytes(
    observations: tuple[_AttemptObservation, ...],
) -> bytes:
    payload = bytearray()
    expected_sequence = 1
    for item in observations:
        if item.sequence != expected_sequence:
            raise BoundedRetryStateMachineError("reference sequence is not contiguous")
        event = item.event
        fields = (
            "attempt",
            str(item.sequence),
            event.state,
            str(event.visit),
            str(event.attempt),
            event.outcome,
            event.directive,
            event.detail,
            item.resolution,
        )
        payload.extend("\t".join(fields).encode("utf-8"))
        payload.extend(b"\n")
        expected_sequence += 1
    return bytes(payload)


def _reference_terminal_bytes(item: _TerminalObservation) -> bytes:
    fields = (
        "terminal",
        item.terminal,
        item.reason,
        str(item.total),
        item.cause_state,
        str(item.cause_visit),
        str(item.cause_attempt),
        item.cause_outcome,
    )
    return "\t".join(fields).encode("utf-8") + b"\n"


def _reference_simulate(
    events: tuple[_Event, ...],
    parameters: BoundedRetryStateMachineParameters,
) -> tuple[tuple[_AttemptObservation, ...], _TerminalObservation]:
    if len(events) == 0:
        return (), _reference_empty_terminal()
    observations: list[_AttemptObservation] = []
    counters = {state: 0 for state in _STATES[parameters.transition_model]}
    if parameters.transition_model == "linear":
        agenda = ["prepare", "execute", "publish"]
        for state in agenda:
            counters[state] += 1
            status, event, reason = _reference_run_visit(
                events,
                parameters.retry_policy,
                state,
                counters[state],
                observations,
            )
            if status != "success":
                return tuple(observations), _reference_failure_terminal(
                    observations, state, counters[state], event, reason
                )
        return tuple(observations), _reference_success_terminal(
            observations, "complete", "workflow-complete"
        )

    if parameters.transition_model == "branching":
        counters["choose"] = 1
        status, choice, reason = _reference_run_visit(
            events, parameters.retry_policy, "choose", 1, observations
        )
        if status != "success":
            return tuple(observations), _reference_failure_terminal(
                observations, "choose", 1, choice, reason
            )
        if choice is None or choice.directive not in {"fast", "safe"}:
            raise BoundedRetryStateMachineError("reference branch choice is invalid")
        branch = choice.directive
        for state in (branch, "publish"):
            counters[state] += 1
            status, event, reason = _reference_run_visit(
                events,
                parameters.retry_policy,
                state,
                counters[state],
                observations,
            )
            if status != "success":
                return tuple(observations), _reference_failure_terminal(
                    observations, state, counters[state], event, reason
                )
        return tuple(observations), _reference_success_terminal(
            observations, "complete", "workflow-complete"
        )

    if parameters.transition_model == "cyclic-bounded":
        for cycle in range(1, 4):
            for state in ("check", "work"):
                counters[state] += 1
                status, event, reason = _reference_run_visit(
                    events,
                    parameters.retry_policy,
                    state,
                    counters[state],
                    observations,
                )
                if status != "success":
                    return tuple(observations), _reference_failure_terminal(
                        observations, state, counters[state], event, reason
                    )
                if state == "work":
                    if event is None:
                        raise BoundedRetryStateMachineError("work success is missing")
                    if event.directive == "finish":
                        return tuple(observations), _reference_success_terminal(
                            observations, "complete", "workflow-complete"
                        )
                    if event.directive != "repeat":
                        raise BoundedRetryStateMachineError("work route is invalid")
            if cycle == 3:
                return tuple(observations), _reference_success_terminal(
                    observations, "cycle-limit", "cycle-bound-exceeded"
                )
        raise BoundedRetryStateMachineError("reference cycle escaped")

    counters["prepare"] = 1
    status, event, reason = _reference_run_visit(
        events, parameters.retry_policy, "prepare", 1, observations
    )
    if status != "success":
        return tuple(observations), _reference_failure_terminal(
            observations, "prepare", 1, event, reason
        )
    for state in ("apply", "publish"):
        counters[state] = 1
        status, event, reason = _reference_run_visit(
            events, parameters.retry_policy, state, 1, observations
        )
        if status == "success":
            continue
        if status == "missing":
            return tuple(observations), _reference_failure_terminal(
                observations, state, 1, event, reason
            )
        if event is None:
            raise BoundedRetryStateMachineError(
                "reference compensation cause is absent"
            )
        initiating_failure = event
        counters["compensate"] = 1
        compensation_status, compensation, compensation_reason = (
            _reference_run_visit(
                events,
                parameters.retry_policy,
                "compensate",
                1,
                observations,
            )
        )
        if compensation_status == "success":
            return tuple(observations), _reference_event_terminal(
                observations,
                "compensated",
                "compensation-complete",
                initiating_failure,
            )
        return tuple(observations), _reference_failure_terminal(
            observations,
            "compensate",
            1,
            compensation,
            "compensation-failed" if compensation_status != "missing" else compensation_reason,
            terminal="compensation-failed",
        )
    return tuple(observations), _reference_success_terminal(
        observations, "complete", "workflow-complete"
    )


def _expected_output_policy() -> tuple[ExpectedFile, ExpectedFile]:
    return (
        ExpectedFile(
            BOUNDED_RETRY_STATE_MACHINE_ATTEMPTS_OUTPUT,
            BOUNDED_RETRY_STATE_MACHINE_OUTPUT_MAXIMUM_BYTES,
            BOUNDED_RETRY_STATE_MACHINE_OUTPUT_MODE,
        ),
        ExpectedFile(
            BOUNDED_RETRY_STATE_MACHINE_TERMINAL_OUTPUT,
            BOUNDED_RETRY_STATE_MACHINE_OUTPUT_MAXIMUM_BYTES,
            BOUNDED_RETRY_STATE_MACHINE_OUTPUT_MODE,
        ),
    )


def derive_bounded_retry_state_machine_output(
    definition: FixtureDefinition,
    parameters: BoundedRetryStateMachineParameters,
) -> BoundedRetryStateMachineOutput:
    if type(parameters) is not BoundedRetryStateMachineParameters:
        raise BoundedRetryStateMachineError("parameters have the wrong exact type")
    parameters.__post_init__()
    checked = _revalidate_definition(definition)
    if checked.expected_files != _expected_output_policy():
        raise BoundedRetryStateMachineError("output policy differs from contract")
    events = _primary_parse_events(checked, parameters.transition_model)
    attempts, terminal = _primary_simulate(events, parameters)
    return BoundedRetryStateMachineOutput(
        _attempts_bytes(attempts), _terminal_bytes(terminal)
    )


def reference_bounded_retry_state_machine_output(
    definition: FixtureDefinition,
    parameters: BoundedRetryStateMachineParameters,
) -> BoundedRetryStateMachineOutput:
    if type(parameters) is not BoundedRetryStateMachineParameters:
        raise BoundedRetryStateMachineError("reference parameters have wrong type")
    parameters.__post_init__()
    checked = _revalidate_definition(definition)
    if checked.expected_files != _expected_output_policy():
        raise BoundedRetryStateMachineError("reference output policy differs")
    events = _reference_parse_events(checked, parameters.transition_model)
    attempts, terminal = _reference_simulate(events, parameters)
    return BoundedRetryStateMachineOutput(
        _reference_attempts_bytes(attempts),
        _reference_terminal_bytes(terminal),
    )


def verify_bounded_retry_state_machine_output(
    definition: FixtureDefinition,
    parameters: BoundedRetryStateMachineParameters,
    candidate_output: BoundedRetryStateMachineOutput,
) -> bool:
    if type(candidate_output) is not BoundedRetryStateMachineOutput:
        return False
    try:
        candidate_output.__post_init__()
        primary = derive_bounded_retry_state_machine_output(definition, parameters)
        reference = reference_bounded_retry_state_machine_output(definition, parameters)
    except (BoundedRetryStateMachineError, TypeError, ValueError):
        return False
    return primary == reference == candidate_output


def _compute_oracle_sha256(outputs: tuple[OracleOutputRecord, ...]) -> str:
    if (
        type(outputs) is not tuple
        or len(outputs) != 2
        or any(type(output) is not OracleOutputRecord for output in outputs)
    ):
        raise BoundedRetryStateMachineError("oracle outputs are invalid")
    for output in outputs:
        output.__post_init__()
    expected_paths = (
        BOUNDED_RETRY_STATE_MACHINE_ATTEMPTS_OUTPUT,
        BOUNDED_RETRY_STATE_MACHINE_TERMINAL_OUTPUT,
    )
    if tuple(output.path for output in outputs) != expected_paths or any(
        output.mode != BOUNDED_RETRY_STATE_MACHINE_OUTPUT_MODE
        or len(output.content) > BOUNDED_RETRY_STATE_MACHINE_OUTPUT_MAXIMUM_BYTES
        for output in outputs
    ):
        raise BoundedRetryStateMachineError("oracle output contract differs")
    return domain_sha256(
        "cbds.executable-fixture.trusted-oracle.v1",
        {
            "schema_version": EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION,
            "semantic_verifier_identity": BOUNDED_RETRY_STATE_MACHINE_VERIFIER_IDENTITY,
            "outputs": [output.commitment_record() for output in outputs],
        },
    )


@dataclass(frozen=True, slots=True)
class BoundedRetryStateMachineOracle:
    outputs: tuple[OracleOutputRecord, ...]
    oracle_sha256: str
    semantic_verifier_identity: str = BOUNDED_RETRY_STATE_MACHINE_VERIFIER_IDENTITY
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            type(self.outputs) is not tuple
            or type(self.semantic_verifier_identity) is not str
            or self.semantic_verifier_identity
            != BOUNDED_RETRY_STATE_MACHINE_VERIFIER_IDENTITY
            or type(self.schema_version) is not str
            or self.schema_version != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
            or not _is_sha256(self.oracle_sha256)
            or self.oracle_sha256 != _compute_oracle_sha256(self.outputs)
        ):
            raise BoundedRetryStateMachineError("oracle identity is invalid")

    def commitment_record(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "schema_version": self.schema_version,
            "record_type": "cbds.executable-fixture-trusted-oracle",
            "semantic_verifier_identity": self.semantic_verifier_identity,
            "outputs": [item.commitment_record() for item in self.outputs],
            "oracle_sha256": self.oracle_sha256,
        }


@dataclass(frozen=True, slots=True)
class BoundedRetryStateMachineFixtureBundle:
    task_contract_sha256: str
    profile_sha256: str
    definition: FixtureDefinition = field(repr=False)
    fixture_definition_sha256: str
    oracle: BoundedRetryStateMachineOracle = field(repr=False)
    descriptor: OpaqueFixtureDescriptor
    schema_version: str = EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
    candidate_execution_authorized: bool = False
    model_selection_eligible: bool = False
    claim_authorized: bool = False

    def __post_init__(self) -> None:
        validate_bounded_retry_state_machine_fixture_bundle(self)

    def to_opaque_descriptor(self) -> OpaqueFixtureDescriptor:
        validate_bounded_retry_state_machine_fixture_bundle(self)
        return self.descriptor

    def commitment_record(self) -> dict[str, object]:
        validate_bounded_retry_state_machine_fixture_bundle(self)
        return {
            "schema_version": self.schema_version,
            "record_type": "cbds.executable-fixture-private-binding",
            "binding_version": EXECUTABLE_FIXTURE_BINDING_VERSION,
            "task_contract_sha256": self.task_contract_sha256,
            "profile_sha256": self.profile_sha256,
            "fixture_definition_sha256": self.fixture_definition_sha256,
            "oracle": self.oracle.commitment_record(),
            "descriptor": self.descriptor.to_public_record(),
            "candidate_execution_authorized": False,
            "model_selection_eligible": False,
            "claim_authorized": False,
        }


def validate_bounded_retry_state_machine_fixture_bundle(
    bundle: BoundedRetryStateMachineFixtureBundle,
) -> None:
    if type(bundle) is not BoundedRetryStateMachineFixtureBundle:
        raise BoundedRetryStateMachineError("bundle has the wrong exact type")
    if (
        type(bundle.schema_version) is not str
        or bundle.schema_version != EXECUTABLE_FIXTURE_BUNDLE_SCHEMA_VERSION
        or not _is_sha256(bundle.task_contract_sha256)
        or not _is_sha256(bundle.profile_sha256)
        or not _is_sha256(bundle.fixture_definition_sha256)
        or bundle.candidate_execution_authorized is not False
        or bundle.model_selection_eligible is not False
        or bundle.claim_authorized is not False
    ):
        raise BoundedRetryStateMachineError("bundle metadata is invalid")
    definition = _revalidate_definition(bundle.definition)
    if (
        bundle.fixture_definition_sha256
        != compute_fixture_definition_semantic_sha256(definition)
        or definition.expected_files != _expected_output_policy()
    ):
        raise BoundedRetryStateMachineError("fixture definition identity is invalid")
    if type(bundle.oracle) is not BoundedRetryStateMachineOracle:
        raise BoundedRetryStateMachineError("oracle has the wrong exact type")
    bundle.oracle.__post_init__()
    if type(bundle.descriptor) is not OpaqueFixtureDescriptor:
        raise BoundedRetryStateMachineError("descriptor has the wrong exact type")
    bundle.descriptor.__post_init__()
    fixture_sha256 = compute_bound_fixture_sha256(
        task_contract_sha256=bundle.task_contract_sha256,
        profile_sha256=bundle.profile_sha256,
        fixture_definition_sha256=bundle.fixture_definition_sha256,
        oracle_sha256=bundle.oracle.oracle_sha256,
    )
    if (
        bundle.descriptor.fixture_sha256 != fixture_sha256
        or bundle.descriptor.fixture_id != f"fx-{fixture_sha256[:24]}"
        or bundle.descriptor.task_contract_sha256 != bundle.task_contract_sha256
    ):
        raise BoundedRetryStateMachineError("descriptor binding is invalid")


def verify_bounded_retry_state_machine_fixture_bundle(bundle: object) -> bool:
    try:
        validate_bounded_retry_state_machine_fixture_bundle(bundle)  # type: ignore[arg-type]
    except (BoundedRetryStateMachineError, TypeError, ValueError):
        return False
    return True


def _validate_task_profile(
    task: object, profile: object
) -> tuple[BoundedRetryStateMachineTask, ExecutableFixtureProfile]:
    if type(task) is not BoundedRetryStateMachineTask:
        raise BoundedRetryStateMachineError("task has the wrong exact type")
    if type(profile) is not ExecutableFixtureProfile:
        raise BoundedRetryStateMachineError("profile has the wrong exact type")
    try:
        task.__post_init__()
        BoundedRetryStateMachineParameters(
            task.parameters.transition_model,
            task.parameters.retry_policy,
        )
        rebuilt_profile = ExecutableFixtureProfile(
            profile_id=profile.profile_id,
            cases=profile.cases,
            profile_sha256=profile.profile_sha256,
            profile_version=profile.profile_version,
            public_method_development=profile.public_method_development,
            sealed=profile.sealed,
            candidate_execution_authorized=profile.candidate_execution_authorized,
            model_selection_eligible=profile.model_selection_eligible,
            claim_authorized=profile.claim_authorized,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise BoundedRetryStateMachineError("task/profile revalidation failed") from exc
    if rebuilt_profile not in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
        raise BoundedRetryStateMachineError("profile is not public development data")
    return task, profile


def _construct_bounded_retry_state_machine_fixture_bundle(
    task: BoundedRetryStateMachineTask,
    profile: ExecutableFixtureProfile,
) -> BoundedRetryStateMachineFixtureBundle:
    selected_task, selected_profile = _validate_task_profile(task, profile)
    definition = FixtureDefinition(
        fixture_id=(
            f"fixture.{selected_task.task_id}.{selected_profile.profile_id}"
        ),
        inputs=_fixture_inputs(
            selected_profile, selected_task.parameters.transition_model
        ),
        expected_files=_expected_output_policy(),
    )
    primary = derive_bounded_retry_state_machine_output(
        definition, selected_task.parameters
    )
    reference = reference_bounded_retry_state_machine_output(
        definition, selected_task.parameters
    )
    if primary != reference:
        raise BoundedRetryStateMachineError("independent production oracles disagree")
    outputs = (
        OracleOutputRecord(
            BOUNDED_RETRY_STATE_MACHINE_ATTEMPTS_OUTPUT,
            primary.attempts,
            BOUNDED_RETRY_STATE_MACHINE_OUTPUT_MODE,
        ),
        OracleOutputRecord(
            BOUNDED_RETRY_STATE_MACHINE_TERMINAL_OUTPUT,
            primary.terminal,
            BOUNDED_RETRY_STATE_MACHINE_OUTPUT_MODE,
        ),
    )
    oracle = BoundedRetryStateMachineOracle(
        outputs, _compute_oracle_sha256(outputs)
    )
    definition_sha256 = compute_fixture_definition_semantic_sha256(definition)
    fixture_sha256 = compute_bound_fixture_sha256(
        task_contract_sha256=selected_task.task_contract_sha256,
        profile_sha256=selected_profile.profile_sha256,
        fixture_definition_sha256=definition_sha256,
        oracle_sha256=oracle.oracle_sha256,
    )
    return BoundedRetryStateMachineFixtureBundle(
        task_contract_sha256=selected_task.task_contract_sha256,
        profile_sha256=selected_profile.profile_sha256,
        definition=definition,
        fixture_definition_sha256=definition_sha256,
        oracle=oracle,
        descriptor=OpaqueFixtureDescriptor(
            fixture_id=f"fx-{fixture_sha256[:24]}",
            fixture_sha256=fixture_sha256,
            task_contract_sha256=selected_task.task_contract_sha256,
        ),
    )


def build_bounded_retry_state_machine_fixture_bundle(
    task: BoundedRetryStateMachineTask,
    profile: ExecutableFixtureProfile,
) -> BoundedRetryStateMachineFixtureBundle:
    selected_task, selected_profile = _validate_task_profile(task, profile)
    bundle = _construct_bounded_retry_state_machine_fixture_bundle(
        selected_task, selected_profile
    )
    index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(selected_profile)
    if selected_task.fixtures[index] != bundle.descriptor:
        raise BoundedRetryStateMachineError(
            "generated descriptor differs from task binding"
        )
    return bundle


def validate_bounded_retry_state_machine_fixture_for_task_profile(
    task: BoundedRetryStateMachineTask,
    profile: ExecutableFixtureProfile,
    bundle: BoundedRetryStateMachineFixtureBundle,
) -> None:
    selected_task, selected_profile = _validate_task_profile(task, profile)
    validate_bounded_retry_state_machine_fixture_bundle(bundle)
    expected = build_bounded_retry_state_machine_fixture_bundle(
        selected_task, selected_profile
    )
    if bundle != expected:
        raise BoundedRetryStateMachineError("bundle differs from reconstruction")
    index = PUBLIC_DEVELOPMENT_FIXTURE_PROFILES.index(selected_profile)
    if selected_task.fixtures[index] != expected.descriptor:
        raise BoundedRetryStateMachineError("task descriptor differs from fixture")


def verify_bounded_retry_state_machine_fixture_for_task_profile(
    task: object, profile: object, bundle: object
) -> bool:
    try:
        validate_bounded_retry_state_machine_fixture_for_task_profile(
            task,  # type: ignore[arg-type]
            profile,  # type: ignore[arg-type]
            bundle,  # type: ignore[arg-type]
        )
    except (BoundedRetryStateMachineError, TypeError, ValueError):
        return False
    return True


def materialize_bounded_retry_state_machine_fixture(
    task: BoundedRetryStateMachineTask,
    profile: ExecutableFixtureProfile,
    bundle: BoundedRetryStateMachineFixtureBundle,
    workspace: str | os.PathLike[str],
) -> WorkspaceHandle:
    validate_bounded_retry_state_machine_fixture_for_task_profile(
        task, profile, bundle
    )
    return materialize_fixture(bundle.definition, workspace)


def verify_bounded_retry_state_machine_workspace(
    task: BoundedRetryStateMachineTask,
    profile: ExecutableFixtureProfile,
    bundle: BoundedRetryStateMachineFixtureBundle,
    handle: WorkspaceHandle,
) -> bool:
    """Verify an exact quiescent final state without executing a candidate.

    The trusted harness must stop all writers before entry and keep the
    workspace quiescent through return.  A matching report cannot prove actual
    retries, waits, transitions, compensation, tool use, transient input
    preservation, publication history, or candidate exit status.
    """

    if type(handle) is not WorkspaceHandle:
        return False
    try:
        validate_bounded_retry_state_machine_fixture_for_task_profile(
            task, profile, bundle
        )
        baseline = handle.baseline
        if (
            baseline.fixture_id != bundle.definition.fixture_id
            or baseline.fixture_sha256 != bundle.definition.fixture_sha256
            or handle.expected_files != bundle.definition.expected_files
            or baseline.output_scaffold_entries
        ):
            return False
        input_scan = handle.scan_inputs()
        if (
            input_scan.scope != "inputs"
            or input_scan.baseline_sha256 != baseline.baseline_sha256
            or input_scan.entries != baseline.input_entries
            or input_scan.tree_sha256 != baseline.input_tree_sha256
        ):
            return False
        output_scan = handle.scan_outputs()
        output_entries = validate_expected_output_policy(
            bundle.definition, output_scan
        )
        if len(output_entries) != 2 or len(bundle.oracle.outputs) != 2:
            return False
        by_path = {entry.path: entry for entry in output_entries}
        if set(by_path) != {
            BOUNDED_RETRY_STATE_MACHINE_ATTEMPTS_OUTPUT,
            BOUNDED_RETRY_STATE_MACHINE_TERMINAL_OUTPUT,
        } or any(
            entry.mode != BOUNDED_RETRY_STATE_MACHINE_OUTPUT_MODE
            for entry in by_path.values()
        ):
            return False
        primary = derive_bounded_retry_state_machine_output(
            bundle.definition, task.parameters
        )
        reference = reference_bounded_retry_state_machine_output(
            bundle.definition, task.parameters
        )
        if primary != reference:
            return False
        observed_attempts = handle.read_output_bytes(
            output_scan, BOUNDED_RETRY_STATE_MACHINE_ATTEMPTS_OUTPUT
        )
        observed_terminal = handle.read_output_bytes(
            output_scan, BOUNDED_RETRY_STATE_MACHINE_TERMINAL_OUTPUT
        )
        if (
            observed_attempts != primary.attempts
            or observed_terminal != primary.terminal
            or observed_attempts != bundle.oracle.outputs[0].content
            or observed_terminal != bundle.oracle.outputs[1].content
        ):
            return False
        final_input_scan = handle.scan_inputs()
        final_output_scan = handle.scan_outputs()
        return (
            final_input_scan == input_scan
            and final_output_scan == output_scan
            and final_input_scan.entries == baseline.input_entries
            and final_input_scan.tree_sha256 == baseline.input_tree_sha256
        )
    except (
        BoundedRetryStateMachineError,
        ExecutableWorkspaceError,
        OSError,
        TypeError,
        ValueError,
    ):
        return False


__all__ = [
    "BOUNDED_RETRY_STATE_MACHINE_ALLOWED_TOOLS",
    "BOUNDED_RETRY_STATE_MACHINE_ATOMIC_PUBLICATION_HISTORY_OBSERVED",
    "BOUNDED_RETRY_STATE_MACHINE_ATTEMPTS_OUTPUT",
    "BOUNDED_RETRY_STATE_MACHINE_CANDIDATE_EXIT_STATUS_OBSERVED",
    "BOUNDED_RETRY_STATE_MACHINE_DIRECTORY_PERMISSION_ERRORS_COVERED",
    "BOUNDED_RETRY_STATE_MACHINE_EFFECTIVE_ACCESS_FAILURES_COVERED",
    "BOUNDED_RETRY_STATE_MACHINE_EVENT_LEDGER_MAXIMUM_BYTES",
    "BOUNDED_RETRY_STATE_MACHINE_FAMILY_ID",
    "BOUNDED_RETRY_STATE_MACHINE_FILESYSTEM_IDENTITY",
    "BOUNDED_RETRY_STATE_MACHINE_GENERATOR_VERSION",
    "BOUNDED_RETRY_STATE_MACHINE_OUTPUT_IDENTITY",
    "BOUNDED_RETRY_STATE_MACHINE_OUTPUT_MAXIMUM_BYTES",
    "BOUNDED_RETRY_STATE_MACHINE_RETRY_HISTORY_OBSERVED",
    "BOUNDED_RETRY_STATE_MACHINE_RETRY_POLICIES",
    "BOUNDED_RETRY_STATE_MACHINE_SYMLINK_DISTRACTORS_COVERED",
    "BOUNDED_RETRY_STATE_MACHINE_TERMINAL_OUTPUT",
    "BOUNDED_RETRY_STATE_MACHINE_TOOL_HISTORY_OBSERVED",
    "BOUNDED_RETRY_STATE_MACHINE_TRANSIENT_INPUT_PRESERVATION_OBSERVED",
    "BOUNDED_RETRY_STATE_MACHINE_TRANSITION_HISTORY_OBSERVED",
    "BOUNDED_RETRY_STATE_MACHINE_TRANSITION_MODELS",
    "BOUNDED_RETRY_STATE_MACHINE_VERIFIER_IDENTITY",
    "BOUNDED_RETRY_STATE_MACHINE_WAIT_HISTORY_OBSERVED",
    "BOUNDED_RETRY_STATE_MACHINE_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE",
    "BOUNDED_RETRY_STATE_MACHINE_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE",
    "BoundedRetryStateMachineError",
    "BoundedRetryStateMachineFixtureBundle",
    "BoundedRetryStateMachineOracle",
    "BoundedRetryStateMachineOutput",
    "BoundedRetryStateMachineParameters",
    "BoundedRetryStateMachineTask",
    "bounded_retry_state_machine_task_semantic_core",
    "build_bounded_retry_state_machine_fixture_bundle",
    "build_bounded_retry_state_machine_tasks",
    "compute_bounded_retry_state_machine_task_sha256",
    "derive_bounded_retry_state_machine_output",
    "materialize_bounded_retry_state_machine_fixture",
    "reference_bounded_retry_state_machine_output",
    "validate_bounded_retry_state_machine_fixture_bundle",
    "validate_bounded_retry_state_machine_fixture_for_task_profile",
    "verify_bounded_retry_state_machine_fixture_bundle",
    "verify_bounded_retry_state_machine_fixture_for_task_profile",
    "verify_bounded_retry_state_machine_output",
    "verify_bounded_retry_state_machine_workspace",
]
