"""Deterministic benchmark preparation for terminal-specialization research.

The module deliberately uses only the Python standard library.  It produces
immutable in-memory specifications and canonical JSONL artifacts whose hashes
can be recorded in an experiment manifest.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Final, Literal, TypeAlias, cast


SuiteName: TypeAlias = Literal["static", "interactive"]
SplitName: TypeAlias = Literal[
    "train",
    "operator_selection",
    "method_development",
    "shadow_validation",
    "sealed_id",
    "sealed_ood",
]

SPLIT_NAMES: Final[tuple[SplitName, ...]] = (
    "train",
    "operator_selection",
    "method_development",
    "shadow_validation",
    "sealed_id",
    "sealed_ood",
)
SUITE_NAMES: Final[tuple[SuiteName, ...]] = ("static", "interactive")
BENCHMARK_SCHEMA_VERSION: Final[str] = "1.0.0"
BENCHMARK_GENERATOR_VERSION: Final[str] = "1.0.0"
DETERMINISTIC_SAMPLER: Final[str] = "sha256-counter-rejection-v1"

EDGE_CASE_TAGS: Final[tuple[str, ...]] = (
    "spaces",
    "unicode",
    "leading_dashes",
    "glob_characters",
    "empty_data",
    "duplicate_records",
    "symlinks",
    "ordering_variation",
    "partial_failure",
    "permission_errors",
)

_OPERATORS: Final[tuple[tuple[str, str, str], ...]] = (
    ("discover_files", "find", "shell"),
    ("filter_regex", "grep", "shell"),
    ("transform_text", "sed", "shell"),
    ("aggregate_fields", "awk", "shell"),
    ("select_json", "jq", "shell"),
    ("sort_records", "sort", "shell"),
    ("deduplicate", "uniq", "shell"),
    ("archive_tree", "tar", "shell"),
    ("compute_checksum", "sha256sum", "shell"),
    ("change_permissions", "chmod", "shell"),
    ("inspect_processes", "ps", "shell"),
    ("walk_with_stdlib", "python3", "python"),
)
_FILESYSTEM_SCHEMAS: Final[tuple[str, ...]] = (
    "flat_mixed_files",
    "nested_project_tree",
    "symlinked_dataset",
    "permission_boundary",
    "structured_records",
    "process_workspace",
)
_OUTPUT_CONTRACTS: Final[tuple[str, ...]] = (
    "newline_sorted_paths",
    "tabular_aggregate",
    "canonical_json",
    "filesystem_postcondition",
    "checksum_records",
    "exit_status_and_summary",
)


def canonical_json(value: object) -> str:
    """Return the project's canonical, UTF-8-friendly JSON representation."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _digest(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


class _StableSampler:
    """Versioned hash-based sampling independent of ``random.Random`` internals."""

    def __init__(self, context: object) -> None:
        self._key = canonical_json(
            {
                "algorithm": DETERMINISTIC_SAMPLER,
                "context": context,
            }
        ).encode("utf-8")
        self._counter = 0

    def _uint256(self) -> int:
        counter = self._counter.to_bytes(16, "big")
        self._counter += 1
        return int.from_bytes(sha256(self._key + counter).digest(), "big")

    def randbelow(self, bound: int) -> int:
        if isinstance(bound, bool) or not isinstance(bound, int) or bound <= 0:
            raise ValueError("bound must be a positive integer")
        space = 1 << 256
        limit = space - (space % bound)
        while True:
            candidate = self._uint256()
            if candidate < limit:
                return candidate % bound

    def choice(self, values: Sequence[Any]) -> Any:
        if not values:
            raise ValueError("cannot choose from an empty sequence")
        return values[self.randbelow(len(values))]

    def shuffle(self, values: list[Any]) -> None:
        for index in range(len(values) - 1, 0, -1):
            other = self.randbelow(index + 1)
            values[index], values[other] = values[other], values[index]

    def sample(self, values: Sequence[Any], count: int) -> list[Any]:
        if count < 0 or count > len(values):
            raise ValueError("sample count is outside the population")
        pool = list(values)
        for index in range(count):
            other = index + self.randbelow(len(pool) - index)
            pool[index], pool[other] = pool[other], pool[index]
        return pool[:count]


def _as_nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


@dataclass(frozen=True, slots=True)
class SplitCounts:
    """Counts for the six preregistered dataset splits."""

    train: int = 12
    operator_selection: int = 4
    method_development: int = 3
    shadow_validation: int = 3
    sealed_id: int = 4
    sealed_ood: int = 3

    def __post_init__(self) -> None:
        for name in SPLIT_NAMES:
            _as_nonnegative_int(getattr(self, name), name)

    def as_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in SPLIT_NAMES}

    @classmethod
    def from_mapping(
        cls, value: Mapping[str, object], *, defaults: SplitCounts | None = None
    ) -> SplitCounts:
        unknown = set(value).difference(SPLIT_NAMES)
        if unknown:
            raise ValueError(f"unknown split count keys: {sorted(unknown)!r}")
        base = defaults or cls()
        values = {
            name: _as_nonnegative_int(value.get(name, getattr(base, name)), name)
            for name in SPLIT_NAMES
        }
        return cls(**values)


@dataclass(frozen=True, slots=True)
class BenchmarkConfig:
    """Configuration accepted by generation and preparation APIs.

    The constructor defaults are intentionally small enough for tests.  Use
    :meth:`plan_scale` for the preregistered research counts.
    """

    seed: int = 0
    fixture_count: int = 5
    family_size: int = 4
    static: SplitCounts = SplitCounts()
    interactive: SplitCounts = SplitCounts(
        train=8,
        operator_selection=4,
        method_development=2,
        shadow_validation=2,
        sealed_id=3,
        sealed_ood=2,
    )

    def __post_init__(self) -> None:
        if isinstance(self.seed, bool) or not isinstance(self.seed, int):
            raise ValueError("seed must be an integer")
        fixture_count = _as_nonnegative_int(self.fixture_count, "fixture_count")
        family_size = _as_nonnegative_int(self.family_size, "family_size")
        if fixture_count < 5:
            raise ValueError("fixture_count must be at least 5")
        if family_size < 1:
            raise ValueError("family_size must be at least 1")

    def as_dict(self) -> dict[str, object]:
        return {
            "seed": self.seed,
            "fixture_count": self.fixture_count,
            "family_size": self.family_size,
            "static": self.static.as_dict(),
            "interactive": self.interactive.as_dict(),
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> BenchmarkConfig:
        unknown = set(value).difference(
            {"seed", "fixture_count", "family_size", "static", "interactive"}
        )
        if unknown:
            raise ValueError(f"unknown benchmark config keys: {sorted(unknown)!r}")
        defaults = cls()
        static_value = value.get("static", defaults.static.as_dict())
        interactive_value = value.get(
            "interactive", defaults.interactive.as_dict()
        )
        if not isinstance(static_value, Mapping):
            raise ValueError("static must be a mapping of split names to counts")
        if not isinstance(interactive_value, Mapping):
            raise ValueError(
                "interactive must be a mapping of split names to counts"
            )
        seed = value.get("seed", defaults.seed)
        fixture_count = value.get("fixture_count", defaults.fixture_count)
        family_size = value.get("family_size", defaults.family_size)
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise ValueError("seed must be an integer")
        return cls(
            seed=seed,
            fixture_count=_as_nonnegative_int(fixture_count, "fixture_count"),
            family_size=_as_nonnegative_int(family_size, "family_size"),
            static=SplitCounts.from_mapping(
                cast(Mapping[str, object], static_value), defaults=defaults.static
            ),
            interactive=SplitCounts.from_mapping(
                cast(Mapping[str, object], interactive_value),
                defaults=defaults.interactive,
            ),
        )

    @classmethod
    def plan_scale(cls, *, seed: int = 0) -> BenchmarkConfig:
        return cls(
            seed=seed,
            static=SplitCounts(
                train=12_000,
                operator_selection=1_000,
                method_development=500,
                shadow_validation=500,
                sealed_id=1_000,
                sealed_ood=500,
            ),
            interactive=SplitCounts(
                train=3_000,
                operator_selection=500,
                method_development=250,
                shadow_validation=250,
                sealed_id=500,
                sealed_ood=250,
            ),
        )


@dataclass(frozen=True, slots=True)
class OperatorNode:
    name: str
    parameters: tuple[str, ...]

    def to_record(self) -> dict[str, object]:
        return {"name": self.name, "parameters": list(self.parameters)}

    @classmethod
    def from_record(cls, value: Mapping[str, object]) -> OperatorNode:
        parameters = value.get("parameters")
        if not isinstance(parameters, list) or not all(
            isinstance(item, str) for item in parameters
        ):
            raise ValueError("operator parameters must be a list of strings")
        name = value.get("name")
        if not isinstance(name, str):
            raise ValueError("operator name must be a string")
        return cls(name=name, parameters=tuple(parameters))


@dataclass(frozen=True, slots=True)
class NormalizedSemanticGraph:
    """Canonical operator/dependency graph used as the leakage unit."""

    nodes: tuple[OperatorNode, ...]
    dependencies: tuple[tuple[int, int], ...]

    def __post_init__(self) -> None:
        size = len(self.nodes)
        for source, target in self.dependencies:
            if source < 0 or target < 0 or source >= size or target >= size:
                raise ValueError("graph dependency references a missing node")
            if source >= target:
                raise ValueError("dependencies must follow canonical node order")

    def to_record(self) -> dict[str, object]:
        return {
            "nodes": [node.to_record() for node in self.nodes],
            "dependencies": [list(edge) for edge in self.dependencies],
        }

    @classmethod
    def from_record(
        cls, value: Mapping[str, object]
    ) -> NormalizedSemanticGraph:
        raw_nodes = value.get("nodes")
        raw_dependencies = value.get("dependencies")
        if not isinstance(raw_nodes, list) or not all(
            isinstance(node, Mapping) for node in raw_nodes
        ):
            raise ValueError("graph nodes must be a list of mappings")
        if not isinstance(raw_dependencies, list):
            raise ValueError("graph dependencies must be a list")
        dependencies: list[tuple[int, int]] = []
        for edge in raw_dependencies:
            if (
                not isinstance(edge, list)
                or len(edge) != 2
                or not all(isinstance(item, int) for item in edge)
            ):
                raise ValueError("each dependency must contain two integers")
            dependencies.append((edge[0], edge[1]))
        return cls(
            nodes=tuple(OperatorNode.from_record(node) for node in raw_nodes),
            dependencies=tuple(dependencies),
        )

    @property
    def hash(self) -> str:
        return _digest(self.to_record())


@dataclass(frozen=True, slots=True)
class FixtureSpec:
    fixture_id: str
    seed: int
    edge_case_tags: tuple[str, ...]
    filesystem_variant: str
    expected_contract: str

    def to_record(self) -> dict[str, object]:
        return {
            "fixture_id": self.fixture_id,
            "seed": self.seed,
            "edge_case_tags": list(self.edge_case_tags),
            "filesystem_variant": self.filesystem_variant,
            "expected_contract": self.expected_contract,
        }

    @classmethod
    def from_record(cls, value: Mapping[str, object]) -> FixtureSpec:
        fixture_id = value.get("fixture_id")
        seed = value.get("seed")
        tags = value.get("edge_case_tags")
        filesystem_variant = value.get("filesystem_variant")
        expected_contract = value.get("expected_contract")
        if not isinstance(fixture_id, str):
            raise ValueError("fixture_id must be a string")
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise ValueError("fixture seed must be an integer")
        if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
            raise ValueError("fixture edge_case_tags must be a list of strings")
        if not isinstance(filesystem_variant, str):
            raise ValueError("fixture filesystem_variant must be a string")
        if not isinstance(expected_contract, str):
            raise ValueError("fixture expected_contract must be a string")
        return cls(
            fixture_id=fixture_id,
            seed=seed,
            edge_case_tags=tuple(tags),
            filesystem_variant=filesystem_variant,
            expected_contract=expected_contract,
        )


@dataclass(frozen=True, slots=True)
class SemanticSpec:
    """One immutable benchmark specification."""

    spec_id: str
    suite: SuiteName
    split: SplitName
    semantic_family: str
    semantic_signature: str
    graph: NormalizedSemanticGraph
    graph_hash: str
    prompt: str
    utility_composition: tuple[str, ...]
    filesystem_schema: str
    solution_family: str
    output_contract: str
    edge_case_tags: tuple[str, ...]
    fixtures: tuple[FixtureSpec, ...]
    max_actions: int | None = None

    def to_record(self) -> dict[str, object]:
        return {
            "spec_id": self.spec_id,
            "suite": self.suite,
            "split": self.split,
            "semantic_family": self.semantic_family,
            "semantic_signature": self.semantic_signature,
            "graph": self.graph.to_record(),
            "graph_hash": self.graph_hash,
            "prompt": self.prompt,
            "utility_composition": list(self.utility_composition),
            "filesystem_schema": self.filesystem_schema,
            "solution_family": self.solution_family,
            "output_contract": self.output_contract,
            "edge_case_tags": list(self.edge_case_tags),
            "fixtures": [fixture.to_record() for fixture in self.fixtures],
            "max_actions": self.max_actions,
        }

    @classmethod
    def from_record(cls, value: Mapping[str, object]) -> SemanticSpec:
        def required_string(name: str) -> str:
            item = value.get(name)
            if not isinstance(item, str):
                raise ValueError(f"{name} must be a string")
            return item

        suite = required_string("suite")
        split = required_string("split")
        if suite not in SUITE_NAMES:
            raise ValueError(f"unknown suite: {suite!r}")
        if split not in SPLIT_NAMES:
            raise ValueError(f"unknown split: {split!r}")
        graph_value = value.get("graph")
        fixtures_value = value.get("fixtures")
        utilities = value.get("utility_composition")
        edge_tags = value.get("edge_case_tags")
        max_actions = value.get("max_actions")
        if not isinstance(graph_value, Mapping):
            raise ValueError("graph must be a mapping")
        if not isinstance(fixtures_value, list) or not all(
            isinstance(fixture, Mapping) for fixture in fixtures_value
        ):
            raise ValueError("fixtures must be a list of mappings")
        if not isinstance(utilities, list) or not all(
            isinstance(utility, str) for utility in utilities
        ):
            raise ValueError("utility_composition must be a list of strings")
        if not isinstance(edge_tags, list) or not all(
            isinstance(tag, str) for tag in edge_tags
        ):
            raise ValueError("edge_case_tags must be a list of strings")
        if max_actions is not None and (
            isinstance(max_actions, bool) or not isinstance(max_actions, int)
        ):
            raise ValueError("max_actions must be an integer or null")
        return cls(
            spec_id=required_string("spec_id"),
            suite=cast(SuiteName, suite),
            split=cast(SplitName, split),
            semantic_family=required_string("semantic_family"),
            semantic_signature=required_string("semantic_signature"),
            graph=NormalizedSemanticGraph.from_record(graph_value),
            graph_hash=required_string("graph_hash"),
            prompt=required_string("prompt"),
            utility_composition=tuple(utilities),
            filesystem_schema=required_string("filesystem_schema"),
            solution_family=required_string("solution_family"),
            output_contract=required_string("output_contract"),
            edge_case_tags=tuple(edge_tags),
            fixtures=tuple(
                FixtureSpec.from_record(fixture) for fixture in fixtures_value
            ),
            max_actions=max_actions,
        )


class BenchmarkValidationError(ValueError):
    """Raised with all validation findings, rather than only the first one."""

    def __init__(self, issues: Sequence[str]) -> None:
        self.issues = tuple(issues)
        super().__init__("benchmark validation failed:\n- " + "\n- ".join(issues))


def _fixture_specs(
    *, spec_id: str, seed: int, count: int, output_contract: str
) -> tuple[FixtureSpec, ...]:
    offset = int(_digest({"seed": seed, "spec_id": spec_id})[:8], 16)
    fixtures: list[FixtureSpec] = []
    for index in range(count):
        # With five fixtures, the two-tag windows cover all ten required cases.
        first = (offset + index * 2) % len(EDGE_CASE_TAGS)
        tags = (
            EDGE_CASE_TAGS[first],
            EDGE_CASE_TAGS[(first + 1) % len(EDGE_CASE_TAGS)],
        )
        fixture_seed = int(
            _digest({"seed": seed, "spec_id": spec_id, "fixture": index})[:16],
            16,
        )
        fixtures.append(
            FixtureSpec(
                fixture_id=f"{spec_id}-fx-{index:02d}",
                seed=fixture_seed,
                edge_case_tags=tags,
                filesystem_variant=f"variant-{fixture_seed % 17:02d}",
                expected_contract=output_contract,
            )
        )
    return tuple(fixtures)


def _partition_count(count: int, family_size: int) -> tuple[int, ...]:
    quotient, remainder = divmod(count, family_size)
    parts = [family_size] * quotient
    if remainder:
        parts.append(remainder)
    return tuple(parts)


def _generate_suite(
    *,
    suite: SuiteName,
    counts: SplitCounts,
    config: BenchmarkConfig,
    graph_offset: int,
) -> tuple[SemanticSpec, ...]:
    rng = _StableSampler(
        {"seed": config.seed, "suite": suite, "generator": BENCHMARK_GENERATOR_VERSION}
    )
    specs: list[SemanticSpec] = []
    family_index = 0
    graph_index = graph_offset

    # A family is created and assigned as one indivisible block.  We shuffle
    # the family blocks per split, never individual rows, so no semantic family
    # or signature can be scattered by random row assignment.
    for split in SPLIT_NAMES:
        family_sizes = list(_partition_count(getattr(counts, split), config.family_size))
        rng.shuffle(family_sizes)
        for members in family_sizes:
            family_token = _digest(
                {"seed": config.seed, "suite": suite, "family": family_index}
            )[:16]
            semantic_family = f"{suite}-family-{family_token}"
            operator_count = 2 + rng.randbelow(4)
            operator_indices = rng.sample(range(len(_OPERATORS)), operator_count)
            chosen = tuple(_OPERATORS[index] for index in operator_indices)
            utilities = tuple(sorted({item[1] for item in chosen}))
            solution_family = (
                "python_allowed" if any(item[2] == "python" for item in chosen)
                else "shell_native"
            )
            schema_base = rng.choice(_FILESYSTEM_SCHEMAS)
            # The variant is semantic: it selects a concrete tree schema shared
            # by this family, and therefore belongs in the grouping signature.
            filesystem_schema = f"{schema_base}:layout-{family_index:05d}"
            output_contract = rng.choice(_OUTPUT_CONTRACTS)
            signature_payload = {
                "suite": suite,
                "operators": [item[0] for item in chosen],
                "utilities": utilities,
                "filesystem_schema": filesystem_schema,
                "solution_family": solution_family,
                "output_contract": output_contract,
            }
            semantic_signature = _digest(signature_payload)

            for member_index in range(members):
                # A unique literal threshold changes executable semantics, not
                # merely the row identifier, so graph hashes remain distinct.
                semantic_threshold = graph_index + 1
                nodes = tuple(
                    OperatorNode(
                        name=item[0],
                        parameters=(
                            f"field:{(family_index + node_index) % 7}",
                            f"threshold:{semantic_threshold}",
                            f"mode:{(member_index + node_index) % 5}",
                        ),
                    )
                    for node_index, item in enumerate(chosen)
                )
                dependencies = tuple(
                    (index, index + 1) for index in range(len(nodes) - 1)
                )
                if len(nodes) > 3:
                    dependencies += ((0, len(nodes) - 1),)
                graph = NormalizedSemanticGraph(nodes, dependencies)
                graph_hash = graph.hash
                spec_token = _digest(
                    {
                        "seed": config.seed,
                        "suite": suite,
                        "graph_hash": graph_hash,
                    }
                )[:20]
                spec_id = f"{suite}-{spec_token}"
                action_text = (
                    "Return one program that"
                    if suite == "static"
                    else "Using at most eight terminal actions,"
                )
                prompt = (
                    f"{action_text} applies "
                    + ", then ".join(node.name for node in nodes)
                    + f" to the {filesystem_schema} workspace. Use semantic "
                    + f"threshold {semantic_threshold}; satisfy {output_contract}."
                )
                fixtures = _fixture_specs(
                    spec_id=spec_id,
                    seed=config.seed,
                    count=config.fixture_count,
                    output_contract=output_contract,
                )
                specs.append(
                    SemanticSpec(
                        spec_id=spec_id,
                        suite=suite,
                        split=split,
                        semantic_family=semantic_family,
                        semantic_signature=semantic_signature,
                        graph=graph,
                        graph_hash=graph_hash,
                        prompt=prompt,
                        utility_composition=utilities,
                        filesystem_schema=filesystem_schema,
                        solution_family=solution_family,
                        output_contract=output_contract,
                        edge_case_tags=tuple(
                            sorted(
                                {
                                    tag
                                    for fixture in fixtures
                                    for tag in fixture.edge_case_tags
                                }
                            )
                        ),
                        fixtures=fixtures,
                        max_actions=8 if suite == "interactive" else None,
                    )
                )
                graph_index += 1
            family_index += 1
    return tuple(specs)


def generate_benchmark(
    config: BenchmarkConfig | Mapping[str, object] | None = None,
) -> tuple[SemanticSpec, ...]:
    """Generate both suites deterministically from ``config``."""

    resolved = _resolve_config(config)
    static_specs = _generate_suite(
        suite="static",
        counts=resolved.static,
        config=resolved,
        graph_offset=0,
    )
    interactive_specs = _generate_suite(
        suite="interactive",
        counts=resolved.interactive,
        config=resolved,
        graph_offset=len(static_specs),
    )
    specs = static_specs + interactive_specs
    validate_specs(specs, config=resolved)
    return specs


def _resolve_config(
    config: BenchmarkConfig | Mapping[str, object] | None,
) -> BenchmarkConfig:
    if config is None:
        return BenchmarkConfig()
    if isinstance(config, BenchmarkConfig):
        return config
    if isinstance(config, Mapping):
        return BenchmarkConfig.from_mapping(config)
    raise TypeError("config must be a BenchmarkConfig, mapping, or None")


def validate_specs(
    specs: Iterable[SemanticSpec],
    *,
    config: BenchmarkConfig | Mapping[str, object] | None = None,
) -> None:
    """Validate identity, graph uniqueness, split isolation, and counts.

    All findings are returned together via :class:`BenchmarkValidationError`.
    """

    materialized = tuple(specs)
    issues: list[str] = []
    id_counts = Counter(spec.spec_id for spec in materialized)
    graph_counts = Counter(spec.graph_hash for spec in materialized)
    for spec_id, count in sorted(id_counts.items()):
        if count > 1:
            issues.append(f"duplicate spec_id {spec_id!r} ({count} occurrences)")
    for graph_hash, count in sorted(graph_counts.items()):
        if count > 1:
            issues.append(
                f"duplicate graph_hash {graph_hash!r} ({count} occurrences)"
            )

    families: defaultdict[tuple[str, str], set[str]] = defaultdict(set)
    family_signatures: defaultdict[tuple[str, str], set[str]] = defaultdict(set)
    signatures: defaultdict[tuple[str, str], set[str]] = defaultdict(set)
    actual_counts: Counter[tuple[str, str]] = Counter()
    for spec in materialized:
        actual_counts[(spec.suite, spec.split)] += 1
        if spec.suite not in SUITE_NAMES:
            issues.append(f"{spec.spec_id}: unknown suite {spec.suite!r}")
        if spec.split not in SPLIT_NAMES:
            issues.append(f"{spec.spec_id}: unknown split {spec.split!r}")
        if spec.graph_hash != spec.graph.hash:
            issues.append(f"{spec.spec_id}: graph_hash does not match graph content")
        families[(spec.suite, spec.semantic_family)].add(spec.split)
        family_signatures[(spec.suite, spec.semantic_family)].add(
            spec.semantic_signature
        )
        signatures[(spec.suite, spec.semantic_signature)].add(spec.split)
        fixture_ids = [fixture.fixture_id for fixture in spec.fixtures]
        if len(fixture_ids) != len(set(fixture_ids)):
            issues.append(f"{spec.spec_id}: duplicate fixture_id")
        if len(spec.fixtures) < 5:
            issues.append(f"{spec.spec_id}: fewer than five fixtures")
        covered_tags = {
            tag for fixture in spec.fixtures for tag in fixture.edge_case_tags
        }
        missing_tags = set(EDGE_CASE_TAGS).difference(covered_tags)
        if missing_tags:
            issues.append(
                f"{spec.spec_id}: fixtures miss edge cases {sorted(missing_tags)!r}"
            )
        if set(spec.edge_case_tags) != covered_tags:
            issues.append(
                f"{spec.spec_id}: declared edge-case tags differ from fixture coverage"
            )
        if spec.suite == "interactive" and spec.max_actions != 8:
            issues.append(f"{spec.spec_id}: interactive max_actions must equal 8")
        if spec.suite == "static" and spec.max_actions is not None:
            issues.append(f"{spec.spec_id}: static max_actions must be null")

    for (suite, family), splits in sorted(families.items()):
        if len(splits) > 1:
            issues.append(
                f"semantic family leakage for {suite}/{family}: {sorted(splits)!r}"
            )
    for (suite, family), family_signature_set in sorted(
        family_signatures.items()
    ):
        if len(family_signature_set) > 1:
            issues.append(
                f"semantic family {suite}/{family} has multiple signatures"
            )
    for (suite, signature), splits in sorted(signatures.items()):
        if len(splits) > 1:
            issues.append(
                "semantic signature leakage for "
                f"{suite}/{signature}: {sorted(splits)!r}"
            )

    if config is not None:
        resolved = _resolve_config(config)
        for suite, counts in (
            ("static", resolved.static),
            ("interactive", resolved.interactive),
        ):
            for split in SPLIT_NAMES:
                expected = getattr(counts, split)
                actual = actual_counts[(suite, split)]
                if actual != expected:
                    issues.append(
                        f"count mismatch for {suite}/{split}: "
                        f"expected {expected}, found {actual}"
                    )
    if issues:
        raise BenchmarkValidationError(issues)


def _write_jsonl(path: Path, specs: Sequence[SemanticSpec]) -> dict[str, object]:
    payload = "".join(canonical_json(spec.to_record()) + "\n" for spec in specs)
    encoded = payload.encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)
    return {
        "path": path.as_posix(),
        "records": len(specs),
        "bytes": len(encoded),
        "sha256": sha256(encoded).hexdigest(),
    }


def prepare_benchmark(
    config: BenchmarkConfig | Mapping[str, object], output_dir: Path
) -> dict[str, object]:
    """Generate, validate, and write canonical JSONL plus a SHA256 manifest.

    Paths in the returned and persisted manifest are relative to ``output_dir``.
    ``dataset_sha256`` content-addresses the manifest core, while the standard
    ``manifest.sha256`` sidecar hashes the exact bytes of ``manifest.json``.
    """

    resolved = _resolve_config(config)
    if not isinstance(output_dir, Path):
        raise TypeError("output_dir must be a pathlib.Path")
    specs = generate_benchmark(resolved)
    output_dir.mkdir(parents=True, exist_ok=True)
    files: list[dict[str, object]] = []
    for suite in SUITE_NAMES:
        for split in SPLIT_NAMES:
            selected = tuple(
                spec
                for spec in specs
                if spec.suite == suite and spec.split == split
            )
            relative_path = Path(suite) / f"{split}.jsonl"
            file_record = _write_jsonl(output_dir / relative_path, selected)
            file_record["path"] = relative_path.as_posix()
            file_record["suite"] = suite
            file_record["split"] = split
            files.append(file_record)

    manifest_core: dict[str, object] = {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "generator": {
            "name": "cbds.benchmark",
            "version": BENCHMARK_GENERATOR_VERSION,
            "deterministic_sampler": DETERMINISTIC_SAMPLER,
        },
        "config": resolved.as_dict(),
        "total_records": len(specs),
        "files": files,
    }
    dataset_digest = _digest(manifest_core)
    manifest: dict[str, object] = {
        **manifest_core,
        "dataset_hash_scope": "canonical_json_excluding_dataset_hash_fields",
        "dataset_sha256": dataset_digest,
    }
    manifest_bytes = (canonical_json(manifest) + "\n").encode("utf-8")
    (output_dir / "manifest.json").write_bytes(manifest_bytes)
    manifest_digest = sha256(manifest_bytes).hexdigest()
    (output_dir / "manifest.sha256").write_text(
        f"{manifest_digest}  manifest.json\n", encoding="ascii", newline="\n"
    )
    return manifest


def load_jsonl(path: Path) -> tuple[SemanticSpec, ...]:
    """Load typed immutable specifications from a generated JSONL file."""

    specs: list[SemanticSpec] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, Mapping):
                raise ValueError(f"{path}:{line_number}: record must be an object")
            specs.append(SemanticSpec.from_record(value))
    return tuple(specs)


__all__ = [
    "BENCHMARK_GENERATOR_VERSION",
    "BENCHMARK_SCHEMA_VERSION",
    "BenchmarkConfig",
    "BenchmarkValidationError",
    "EDGE_CASE_TAGS",
    "FixtureSpec",
    "NormalizedSemanticGraph",
    "OperatorNode",
    "SPLIT_NAMES",
    "SUITE_NAMES",
    "SemanticSpec",
    "SplitCounts",
    "DETERMINISTIC_SAMPLER",
    "canonical_json",
    "generate_benchmark",
    "load_jsonl",
    "prepare_benchmark",
    "validate_specs",
]
