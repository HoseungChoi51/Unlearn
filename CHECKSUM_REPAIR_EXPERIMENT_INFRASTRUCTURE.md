# Checksum repair-plan experiment infrastructure

## What this tranche is for

`checksum-repair-plan` is the eleventh executable-static development family.
It tests whether a model can parse one of four checksum-manifest encodings,
classify damaged or unavailable assets without following symbolic links, and
publish a deterministic policy-specific repair plan.

This family matters to terminal-specialization research because it combines
binary-safe hashing, structured-input parsing, hostile path handling, batch
error semantics, and structured output. A command that merely runs
`sha256sum -c` is insufficient: the task requires an exact plan whose meaning
changes across five repair policies.

The plan is deliberately declarative. It does not rewrite a checksum
manifest, delete a record, or move a file into quarantine. The frozen tool
budget contains `awk`, `jq`, `mkdir`, `sha256sum`, and `sort`, but no mutation
utility. Treating a proposed action as an executed repair would therefore
misstate both the task and the verifier's evidence.

This tranche is public method-development infrastructure, not a model result.
Its tasks and fixtures are unsealed, unscored, and ineligible for model
selection or research claims.

## The 4-by-5 task grid

The manifest-layout axis is:

- `sha256sum-text`;
- `jsonl`;
- `csv`;
- `nul-pairs`.

The repair-policy axis is:

- `report-only`;
- `replace-digest`;
- `drop-missing`;
- `quarantine-mismatch`;
- `strict-reject`.

The Cartesian product creates 20 task contracts. Each task has the same
asset-classification semantics and differs only in its input wire format and
policy. Five hostile fixture profiles per task create 100 authenticated
fixture/oracle bundles.

## Components and why each matters

### 1. Exact manifest grammars

Each layout has a closed framing contract:

- `sha256sum-text` uses a lowercase 64-character digest, exactly two spaces,
  one restricted literal path, and LF;
- `jsonl` uses strict UTF-8 objects with exactly `path` and `sha256`, rejects
  duplicate keys, and requires LF after every object;
- `csv` uses an exact `path,sha256` header, strict RFC 4180 quoting, two fields
  per data record, and CRLF record endings;
- `nul-pairs` uses repeated path-NUL-digest-NUL pairs with a mandatory final
  NUL.

Paths are canonical relative UTF-8 names below `input/assets/`. Absolute,
empty, dot, dot-dot, ASCII-control, DEL, and backslash forms are rejected. The
restricted common path language keeps the four encodings equivalent for
scored fixtures and prevents a filename escape convention from being
silently inherited from one utility.

Closed grammars matter because a parser that accepts malformed rows in one
layout but drops them in another changes the task. The trusted parser fails
the complete fixture closed instead of inventing a partial accepted subset.

### 2. Semantic manifest multiplicity

Exact duplicate declarations and declarations for the same path with
different digests are retained. Physical input order is nonsemantic. Output
entries are sorted by raw path UTF-8 bytes and then declared digest bytes,
with identical ties retained.

This distinction matters because a repair plan is about manifest records, not
only unique files. Silently deduplicating rows can hide inconsistent expected
digests, while using physical row order would make the same logical manifest
produce different answers after a harmless reorder.

### 3. No-follow asset classification

Every declaration receives one of six statuses:

- `ok`;
- `checksum-mismatch`;
- `missing`;
- `symlink`;
- `directory`;
- `unreadable`.

The classifier checks a named symbolic link before regular-file or existence
logic, so a dangling link remains a symlink rather than becoming missing.
Only a readable regular file receives an actual SHA-256 value. Scored
fixtures exclude special nodes and paths below symbolic-link ancestors, and
regular files with any read bit also have owner-read set. Those exclusions
keep the public fixture semantics realizable with the frozen Bash tool set.

No-follow classification matters because hashing through a symlink can make a
plan refer to bytes outside the declared asset leaf. Separating missing,
directory, symlink, and unreadable states also tests more useful recovery
logic than a single generic failure code.

### 4. Policy-specific action selection

The policies map status to action as follows:

- `report-only` assigns `report` to every row;
- `replace-digest` keeps correct rows, proposes `replace-digest` for a
  mismatch, and leaves every unavailable state `unresolved`;
- `drop-missing` keeps correct rows, proposes `drop-record` only for missing
  assets, and leaves other issues unresolved;
- `quarantine-mismatch` keeps correct rows, proposes `quarantine-asset` only
  for mismatches, and leaves unavailable states unresolved;
- `strict-reject` rejects the complete batch when any row is not `ok`, so
  every row receives `reject-batch`; an all-correct batch is kept.

`replace-digest`, `drop-record`, and `quarantine-asset` count as proposed
repair actions. An unresolved row is counted separately. The batch state is
`clean`, `reported`, `planned`, `partial`, or `rejected` according to the
issue and action totals.

This layer matters because the same detected damage can imply different
operational intent. It also prevents a strict policy from being implemented
as a row-local filter when its meaning is whole-batch rejection.

### 5. Ordered semantic JSONL output

`output/repair-plan.jsonl` begins with one plan object that binds the policy,
state, entry count, issue count, action count, and unresolved count. It then
contains one entry object per manifest record with the path, declared and
actual digests, status, action, and optional action argument.

The output verifier accepts insignificant JSON whitespace and object-key
order, then canonicalizes the objects before comparing them with the trusted
semantic result. It rejects duplicate keys, unknown or missing members,
nonfinite extensions, malformed UTF-8, invalid count types, missing final LF,
row reordering, inconsistent repeated-path classifications, and any
status/action/state/count disagreement.

Semantic acceptance matters because JSON member order is not part of the
format's meaning. Requiring one byte serialization would penalize a correct
program for formatting, while accepting arbitrary JSON without reconstructing
the plan would allow internally inconsistent answers.

### 6. Generator-backed hostile fixtures

The five public profiles cover:

- spaces, Unicode, comma and quote characters, including conflicting
  declarations for one asset;
- leading dashes and literal glob metacharacters plus a missing asset;
- an empty file, exact duplicate records, and distinct paths with duplicate
  contents;
- reversed physical order, mismatches, live and dangling symlinks, and an
  implicitly materialized directory;
- correct, mismatched, unreadable, and missing assets under varied modes.

Unlisted files and links are distractors. Input order is also varied
independently of manifest order.

These fixtures matter because simple ASCII files do not exercise the quoting,
ordering, duplicate, kind, and permission decisions that make checksum repair
scripts fail in real workspaces.

### 7. Cross-checked semantic paths

The primary implementation uses layout-specific parsing, indexed asset maps,
and direct policy selection. The reference implementation uses separately
structured framing, list-based asset classification, and an independently
structured action state machine. These paths separately derive manifest
records, statuses, and policy actions, then intentionally converge through
shared closed datatypes, plan-state/count derivation, cryptographic
primitives, and the final renderer. A fixture is admitted only when the final
objects agree.

The comparison can expose a parser, classifier, or action-selection
disagreement; it cannot expose a common defect in the shared state/count or
rendering surface. Literal policy tests, parser boundary tests, mutation
tests, workspace checks, and the reviewed Bash canary cover that shared
assembly. This is cross-checking evidence, not a claim of complete code
independence.

### 8. Exact final-state and input-preservation verification

The workspace verifier requires exactly one independent mode-0644,
link-count-one report under a real output directory and rejects every extra
output. It authenticates the materialized fixture, compares primary and
reference semantics, checks the report semantically, and brackets its reads
with stable input and output scans.

Input bytes, kinds, modes, mtimes, link counts, visible hardlink topology, and
symlink targets must match the original baseline. Tests mutate or remove
inputs, alter modes and mtimes, substitute output links, add external
hardlinks, corrupt the report, and add unexpected paths.

This matters because a correct-looking plan does not excuse changing the
evidence it describes. Stable scans also narrow the race window, although
they still require a trusted supervisor to establish workspace quiescence.

### 9. Non-recursive predecessor evidence

The through-tenth predecessor layer rebuilds the frozen first nine once,
passes that exact task snapshot into the tenth registry, and reuses it for the
tenth local catalog. It then performs global collision checks across 380
tasks and 1,900 fixtures without creating a new historical digest.

The eleventh registry and catalog append 20 tasks and 100 fixtures to that
exact prefix. This matters because faster additive construction must not
silently replace validation of the earlier evidence chain.

### 10. Fixed reviewed Bash canary

One fixed Bash program parses all four layouts and realizes all five policies
under a `PATH` containing exactly `awk`, `jq`, `mkdir`, `sha256sum`, and
`sort`. It solves all 100 public bundles in normal and optimized Python test
modes. Its literal SHA-256 is
`e25f8114b6ac5c5d6bbec863bcf99ac4fb2313e03519775e02f3ae1390bd699f`.

The canary establishes feasibility inside the declared tool budget. It is not
a caller-selected candidate interface, production sandbox, scored output, or
model result.

### 11. Mutation and discrimination evidence

Tests cover digest length and case, line endings, JSON duplicate and extra
keys, deep nesting and integer limits, CSV quoting and record bounds, NUL
termination and parity, unsafe paths, duplicate-path consistency, output
schema/count/order/action mutations, input bytes and metadata, symlink
targets, output substitutions, and hardlink topology.

The 20 layout/policy cells have distinct committed signatures. The
discrimination SHA-256 is
`f71ba70f0a4d004bed235e897a73c1222c6d2687e4eeb842c008f7878e9457aa`.
Running the core suite under `python -O` confirms that production validation
does not depend on assertions.

### 12. Immutable publication and coverage promotion

The eleventh hash-only manifest publishes task, fixture, generator, verifier,
and cumulative identities without fixture bytes, paths, prompts, or oracle
answers. Its builder uses bounded stable reads and atomic no-replace
publication.

The frozen eleventh identities are:

- task set:
  `e52fb74ece2a94baa9bd1b2f6da25ca103839e1e9666361fe5406c34a36b9bb0`;
- added registry:
  `bd0c14880eb25fa80100c317fa41086c45c59147407a67f03981831bcfdfc100`;
- cumulative suite:
  `f62ba1c1214fc48f194a5dea9c69c04962cc14dbdccfc38640cf4eee833018cb`;
- cumulative catalog:
  `cd4221870ba4bfd5ade5098bddccc15af47865930bf173f05141194f3e0b8177`;
- fixture-discrimination evidence:
  `f71ba70f0a4d004bed235e897a73c1222c6d2687e4eeb842c008f7878e9457aa`;
- canonical 56,202-byte
  [eleventh manifest](reports/executable-eleventh-tranche/manifest.json):
  `d6916730cd81170f067b0669812063fd4071102494fd56174b01672b5cad0d59`.

Coverage v4 and its v3-to-v4 migration preserve the exact historical
coverage records, promote only this family, append the eleventh registry
commitment, and prove the other 24 family declarations unchanged. Their
frozen identities are:

- coverage v4 semantic SHA-256:
  `1bd7a4b6ab721404f1d1eb7a64718ba7df783998bf16cd603afb86eb2420d67c`;
- coverage v4 canonical bytes: 24,590 bytes with SHA-256
  `d003a5748da855257aa93e0c6e1b7a4be2de393ec5faa0dcb32d74156f40b3d7`;
- v3-to-v4 migration semantic SHA-256:
  `667e31ef974829a5114544b1f1164f25c0f7515f67ef5600c979e85a3bcc3d8b`;
- migration canonical bytes: 4,701 bytes with SHA-256
  `a1a783544d76f471688afe5f45eaf0f16c30a6ce04c36d1d5a438d6c8e439b7f`.

The generated
[v4 configuration](configs/executable-method-development-coverage-v4.json)
and
[migration record](configs/executable-method-development-coverage-v3-to-v4-migration.json)
are public allocation evidence, not benchmark completion or scoring authority.

## What the family does not prove

The verifier observes a bounded final declarative plan and preserved inputs.
It does not prove that a proposed digest replacement, record deletion, or
quarantine move was executed. It also cannot prove atomic publication,
candidate tool use, read scope, exit status, transient state, directory
permission failures, special-file handling, paths below symlink ancestors, or
global quiescence.

`replace-digest` can normalize a manifest to corrupted bytes. Its presence is
a requested policy cell, not a recommendation for integrity recovery.

The public fixtures cannot measure sealed generalization, and no model
comparison follows from this tranche. Terminal-specialization or compression
claims still require the matched training arms, capability-support audit,
fresh seeds, protected-capability gates, sealed executable suites, deployment
accounting, and preregistered statistics in `PLAN.md`.
