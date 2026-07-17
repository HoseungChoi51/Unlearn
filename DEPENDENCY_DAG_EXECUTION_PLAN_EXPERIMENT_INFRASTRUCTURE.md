# Dependency-DAG execution-plan experiment infrastructure

## What this tranche is for

`dependency-dag-execution-plan` is the fourteenth executable-static
method-development family. It measures whether one terminal program can
strictly decode a bounded dependency graph, apply one exact ready-node
selection policy, and publish either a complete deterministic topological
plan or a precise cycle report.

This family adds planning semantics that are absent from text transformation,
archive, filesystem, and schema-migration tasks. Dependency-aware execution is
a common scripting requirement for build steps, deployment stages, maintenance
jobs, and data pipelines. The important behavior is not merely recognizing a
cycle or calling a library topological sort: the program must preserve an
encoding-independent graph meaning, distinguish the cyclic core from work
blocked downstream, and implement five intentionally different scheduling
policies.

The tranche is public method-development infrastructure. It is not sealed,
scored, eligible for model selection, or evidence of model quality. Its fixed
source-reviewed feasibility program proves only that the declared contract is
realizable with the allowed tools on the tested runtime.

## The 4-by-5 task grid

The graph-encoding axis is:

- `json-adjacency`;
- `json-edge-list`;
- `csv-edges`;
- `line-oriented-dependencies`.

The Kahn ready-node tie-break axis is:

- `utf8-smallest`;
- `declared-priority`;
- `shortest-depth`;
- `largest-fanout`;
- `stable-input-order`.

Their Cartesian product creates 20 task contracts. Five deterministic public
profiles per task create 100 fixture/oracle bundles.

## Components and why each matters

### 1. Four strict graph encodings

Every task reads exactly `input/graph.data` as strict UTF-8 with no BOM. The
source is nonempty and bounded to 128 KiB. It declares from one through 64
nodes, at most 512 physical dependency references, and at most 256 distinct
edges.

The four codecs have closed, encoding-specific framing and schemas:

- `json-adjacency` is one exactly LF-terminated object containing only
  `nodes`. Each node contains exactly `id`, `priority`, and `depends_on`.
- `json-edge-list` is one exactly LF-terminated object containing exact
  `nodes` and `edges` arrays. Nodes contain only `id` and `priority`; edges
  contain only `dependent` and `prerequisite`.
- `csv-edges` uses strict UTF-8 RFC 4180 records with CRLF framing and the
  exact header `record,node,priority,dependency`. Node and edge rows may
  interleave. The parser rejects bare record delimiters, unescaped quotes,
  and characters after a closing quote even where a permissive standard
  parser might accept them.
- `line-oriented-dependencies` uses nonempty LF-terminated rows of
  `<priority><TAB><node-id>` followed by zero or more prerequisite fields.
  CR bytes and blank rows are invalid.

The JSON parser also bounds depth to 8, decoded nodes to 4,096, and object
width to 128 members. These contracts matter because permissive parsing can
change the graph before planning begins: a duplicate JSON member can overwrite
an earlier value, a CSV quote can shift fields, and a framing mismatch can
silently create or discard a record.

### 2. One encoding-independent graph meaning

Node-array order, CSV node-row order, and line-row order define declaration
order. A node ID is a nonempty exact string, contains no Unicode `Cc` or `Cf`
character, and occupies at most 128 UTF-8 bytes. A priority is an exact
integer from -1,000,000 through 1,000,000; booleans and noncanonical textual
integers are rejected.

An input reference `(dependent, prerequisite)` means the directed edge
prerequisite to dependent. Duplicate node declarations and unknown endpoints
are invalid. Duplicate physical edge references are idempotent and count once.
Self-loops and larger directed cycles are valid graphs; they select the cycle
output state rather than becoming parser failures.

This normalization boundary makes the four encodings comparable. Without it,
the benchmark could accidentally measure codec-specific edge orientation,
duplicate handling, or declaration-order assumptions instead of dependency
planning.

### 3. Five exact Kahn tie-break policies

All plans use Kahn's algorithm. When multiple nodes are ready, the selected
task cell applies one policy:

- `utf8-smallest` chooses the lexicographically smallest raw UTF-8 node ID;
- `declared-priority` chooses the largest numeric priority, then raw UTF-8 ID;
- `shortest-depth` chooses the smallest longest-prerequisite-chain depth,
  then raw UTF-8 ID;
- `largest-fanout` chooses the greatest number of distinct direct dependents,
  then raw UTF-8 ID;
- `stable-input-order` chooses the smallest declaration index.

Depth is zero for a root and one plus the maximum prerequisite depth
otherwise. Fanout counts logical edges after duplicate-edge collapse. These
definitions matter because “stable topological sort” is otherwise
underspecified, and because priority, depth, fanout, raw-byte order, and source
order can each produce a different valid plan.

### 4. Exact cycle and blocked-work semantics

An acyclic graph produces status `valid`, a complete plan, and empty
`blocked_nodes` and `cyclic_nodes` arrays.

If Kahn processing stalls, every partial plan is discarded. Status becomes
`cycle`. `blocked_nodes` is the complete final Kahn residual, including nodes
that are not themselves cyclic but depend on a cycle. `cyclic_nodes` contains
only nodes in a nontrivial strongly connected component or nodes with a
self-loop. Both arrays use raw UTF-8 byte order.

Separating these arrays is operationally important. A downstream deployment
step may be blocked by a configuration cycle without being part of that
cycle. Reporting the whole residual as “cyclic” would misidentify the cause;
reporting only the strongly connected core would omit work that cannot run.

### 5. Closed semantic output

The only permitted output is independent link-count-one mode-0644
`output/execution-plan.json` inside one real mode-0755 `output/` directory.
The JSON object has exactly:

```text
graph_encoding
tie_break_policy
status
node_count
edge_count
plan
blocked_nodes
cyclic_nodes
```

`edge_count` counts distinct logical edges. JSON member order and insignificant
whitespace are not semantic: the verifier strictly decodes the candidate
value, checks its closed types and invariants, canonicalizes it, and compares
that value with the trusted state.

Semantic acceptance avoids turning one JSON serialization style into the
task. The closed object and exact filesystem tree still reject omitted or
extra fields, inconsistent counts, incomplete plans, false cycle membership,
extra paths, symlink outputs, and hardlinked outputs.

### 6. Generator-backed hostile profiles

The five shared public profiles cover:

- spaces, Unicode, quotes, backslashes, priorities, depth, and fanout;
- leading dashes, globs, brackets, and question marks as literal node IDs;
- empty dependency lists, isolated nodes, and repeated physical edges;
- deliberately adversarial declaration order plus an authenticated symlink
  distractor;
- a mode-0400 graph, a mode-000 distractor, priority extrema, a two-node
  cycle, a downstream blocked node, and a self-loop.

The first profile makes all five policies behaviorally distinct, while every
encoding carries the same logical graph. The other profiles pressure quoting,
ordering, duplicate collapse, cycle classification, and input preservation.
Distractors are authenticated state that must remain unchanged; they do not
grant source-discovery or symlink-following permission.

### 7. Two trusted semantic derivations

The primary planner builds indegree and dependent maps, maintains a ready set,
updates longest-path depths incrementally, and derives cyclic membership by
return reachability within the Kahn residual.

The reference planner independently reconstructs prerequisite and dependent
relations from the validated immutable graph. It first derives the residual by
repeated predecessor rescans, computes cyclic membership with a separate
transitive-closure direction, derives full prerequisite depths recursively for
an acyclic graph, and selects each next node by rescanning all unfinished
declarations.

A bundle is admitted only when both paths produce the same state. Tests
monkeypatch primary-only relationship and selection helpers to demonstrate
that the reference planner does not call them. Both paths still share strict
source parsing, validated datatypes, canonical JSON, and hashing, so agreement
is cross-checking evidence rather than proof of complete implementation
independence. Literal worked examples, parser-boundary tests, an
implementation-session randomized differential audit, workspace mutations,
and the fixed canary cover that shared surface.

### 8. Label-free behavioral discrimination

The discrimination signature contains only the selected profile's source-byte
hash and a semantic outcome hash over status, counts, plan, blocked nodes, and
cyclic nodes. It excludes task IDs, prompts, semantic-graph labels, encoding
labels, policy labels, and the echoed axis fields in the output document.

All 20 cells have unique observable signatures. The frozen discrimination
SHA-256 is
`25c9f68985ed918a6e8fe9d36b4b6d8a9bd34bb2cd9b039dff82a9276658c82c`.
This proves that labels do not manufacture the public grid's apparent
distinctness. It does not establish sealed difficulty, model competence, or
usefulness as a terminal-performance score.

### 9. Exact workspace verification

The verifier authenticates the task/profile/bundle relationship, reconstructs
both trusted states, validates the materialized baseline, and checks the
candidate's complete final output semantically.

Every input path, kind, byte, mode, mtime, link count, hardlink relation, and
symlink target must remain unchanged. The verifier reads through bounded
descriptor-relative workspace APIs, rejects missing and extra output state,
and repeats input and output scans after reading the answer.

Repeated stable scans narrow a race window but do not establish global
quiescence. The verifier requires a trusted supervisor to keep the workspace
quiescent. It observes final output and input preservation, not tool history,
read scope, candidate exit status, filesystem atomicity, or transient state.

### 10. Explicit resource boundary

The family separately caps source bytes, decoded JSON structure, declared
nodes, physical references, distinct edges, node-ID bytes, and output bytes.
This prevents duplicate-heavy inputs from bypassing the logical edge ceiling
and prevents deeply nested or very wide JSON from exhausting the decoder
before graph bounds apply.

The output proof constructs both maximum-node valid and cycle documents using
escape-heavy 128-byte IDs. Their canonical encodings fit under the declared
64-KiB file ceiling, which is also the conservative total output reservation
and remains below the shared workspace limit.

The fixed canary tests exact 128/129-byte node-ID, 128-KiB source,
512/513-physical-reference, 256/257-distinct-edge, and 64-node boundaries. A
bound proof establishes internal consistency of the declared contract; it is
not a process-level CPU, memory, or syscall sandbox.

### 11. Fixed Python-permitted feasibility canary

One immutable Bash wrapper runs one embedded standard-library implementation
with `python3 -I -S`. Its restricted `PATH` contains exactly `mkdir` and
`python3`. It solves all 100 public bundles, agrees byte-for-byte with each
canonical oracle, passes the full workspace verifier, and cross-runs under
normal and optimized Python modes.

Its frozen identities are:

- Bash literal SHA-256:
  `28da7b6dba511c534accc63c71c0aa882c69f5f123cb8cdaf641bb0f39681de3`;
- Bash literal length: 18,528 UTF-8 bytes;
- aggregate 100-bundle vector:
  `4a046f4f7f1dd74911b99ea302ff59ce32eefed939c7c94184fcdb893c6b3d0e`;
- exact-boundary vector:
  `3cd482a20e4e108dcac0888207edebfaa135725d23168bbda30902f3fea19c32`;
- malformed-input and fail-closed vector:
  `5ee40cf596e7bb71fed18b1ed14f6dd1a191e26735f75c3309436445f1518635`.

The wrapper rejects an inexact argument domain, a symlink source, malformed
types or framing, invalid bounds, and a preexisting output tree. It is not an
arbitrary-candidate executor. Python isolated mode, a restricted `PATH`, and
the absence of imports such as `subprocess` or `socket` in this one reviewed
literal do not confine Python modules, syscalls, or filesystem reads.

### 12. Append-only registry and publication

The hash-neutral predecessor layer reconstructs the first thirteen registries
and catalogs without adding a digest domain. The fourteenth registry appends
20 tasks and rejects task-ID, task-contract, or semantic-graph collisions
across all 460 tasks. The catalog reuses that exact task evidence, appends 100
bundles, and rejects fixture-ID or fixture-hash collisions across all 2,300
bundles.

The checked-in public report contains only hashes, counts, generator and
verifier identities, the output bound, and explicitly false authority fields.
It contains no fixture bytes, source paths, prompts, or oracle answers. This
append-only structure matters because extending the benchmark must not silently
reinterpret any frozen predecessor task or fixture.

The frozen fourteenth identities are:

- family task-set SHA-256:
  `57860e84d15ba33575b12b365f1f541b2537051a12e45f3ca470f1d14819c279`;
- registry SHA-256:
  `c79de716570fe600f2dd7b1e3569456e6f42774d70143a309809410ad8097709`;
- cumulative suite SHA-256:
  `497aac2c69daf2ff05e28b1f132090f3a380ce8ce215b63869a846d576616cf9`;
- cumulative fixture-catalog SHA-256:
  `11b25fb47af89945a80080b6c42d2fe315076384f3929555c1909cd7c318534b`;
- canonical 56,419-byte report SHA-256:
  `731f3ff9d03befb25ee72a5ed7ea13a17cd30aedfe60cd0d84df9aed5276a490`.

### 13. Coverage-v7 promotion proof

Coverage v7 preserves the exact coverage-v6 artifact and changes only
`dependency-dag-execution-plan` from `planned` to `integrated`. Its v6-to-v7
migration record proves that the other 24 family declarations remain
unchanged, preserves the first four promotion records, appends exactly the
fourteenth source commitment, and retains the family axes, Python-permitted
track, allowed tools, filesystem schema, output contract, and capability
tags.

The promoted family-record SHA-256 is
`142c53602d616c44de495a65d71797d08752d874d0243bec1f75b4e436286ae5`.
The v7 semantic/config-byte SHA-256 values are
`177a97767a528db74951a191282f6d719a34c8a136a21086940dfbd92e5bb569`
and `3742f632c7b5b18f8851d8ce198fe6eebd6ae6dbb1e3cf68a37633d67452f7bc`
for 26,558 canonical bytes. The v6-to-v7 migration semantic/config-byte
SHA-256 values are
`7b1822b390fae8c78bf991d0b348b7033a6d0e33e6fa2318ecdf5a0ae060bee8`
and `ee03276d08386a52a1220bba8de4b6d25a245ab550d4c278c29cef0a1bcf2adc`
for 5,744 canonical bytes.

This promotion is an allocation-status proof. It does not add human review,
sealing, candidate execution, scoring, model selection, or claim authority.
Coverage v6 remains immutable historical evidence.

## Claim boundary

This tranche establishes a deterministic, adversarially tested public
development contract for dependency-aware static planning. It does not
establish:

- sealed generalization or model performance;
- safety or confinement of synthesized or caller-selected programs;
- Python module, syscall, network, or filesystem read confinement;
- candidate tool history, exit status, atomicity, or transient behavior;
- global workspace quiescence;
- independent human-review attestation;
- that the candidate actually used Kahn's algorithm internally;
- that this family is an adequate proxy for build systems, schedulers, or all
  terminal dependency planning.

Those boundaries remain explicit so later model comparisons cannot treat
benchmark construction evidence as a terminal-performance result.
