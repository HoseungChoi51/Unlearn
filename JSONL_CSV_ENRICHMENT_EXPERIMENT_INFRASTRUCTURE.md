# JSONL/CSV enrichment-composition experiment infrastructure

## What this tranche is for

`jsonl-csv-enrichment-compose` is the twelfth executable-static development
family. It tests whether one Bash program can parse two independently encoded
record sources, apply a whole-task missing-field policy, preserve duplicate-key
multiplicity through a left join, and publish one exact semantic JSONL result.

This family is useful to terminal-specialization research because it combines
strict structured-data parsing, quoting, joins, policy-dependent error
handling, deterministic ordering, and final filesystem-state requirements.
These are common terminal-work dependencies that a narrow one-command
benchmark would miss.

The tranche is public method-development infrastructure. It is not sealed,
scored, eligible for model selection, or authorized for a research claim. The
fixed reviewed Bash program establishes feasibility of the task contract; it
is not a model result or a general untrusted-candidate execution boundary.

## The 4-by-5 task grid

The layout axis fixes both source encodings and the logical intermediate
codec:

- `jsonl-left-csv-right` reads JSONL on the left and CSV on the right, with a
  JSONL intermediate;
- `csv-left-jsonl-right` reads CSV on the left and JSONL on the right, with a
  JSONL intermediate;
- `jsonl-both-with-csv-output` reads two JSONL sources and uses a CSV
  intermediate;
- `csv-both-with-jsonl-output` reads two CSV sources and uses a JSONL
  intermediate.

The historical layout names include “output,” but the family-wide final
output contract is always `output/enriched.jsonl`. In this contract the
layout-specific codec names the logical composition-stage representation, not
a second final artifact.

The missing-field-policy axis is:

- `drop-row`;
- `empty-string`;
- `null-value`;
- `emit-reject-row`;
- `reject-source-file`.

The Cartesian product creates 20 task contracts. Five deterministic hostile
profiles per task create 100 fixture/oracle bundles.

## Components and why each matters

### 1. Closed source grammars

Each task reads exactly `input/left.data` and `input/right.data`. Logical left
records contain a nonempty subset of `id,left`; logical right records contain
a nonempty subset of `id,right`.

JSONL requires strict UTF-8, one exact object per LF-terminated physical
record, no duplicate or extra members, and exact strings for every present
value. CSV requires an exact two-column header, CRLF framing, exactly two
fields, RFC-4180-compatible quoting, and no embedded CR or LF. An empty CSV
field represents a missing field; a quoted comma or doubled quote remains
data.

Each source is nonempty and bounded to 64 KiB and 128 physical records, with a
CSV header counting toward the record limit. Present fields are bounded to
128 UTF-8 bytes and exclude ASCII controls and DEL.

Closed grammars matter because silent row dropping or permissive type
coercion changes join membership. Boundary tests cover present JSON nulls,
numeric values, duplicate keys, malformed quoting, framing differences, the
128/129-record boundary, the 128/129-byte UTF-8 boundary, and the 64-KiB
source limit.

### 2. Exact missing-field policies

The five policies deliberately express different semantics:

- `drop-row` removes incomplete source rows and valid unmatched left rows;
- `empty-string` fills missing source values with `""` and uses `""` for an
  unmatched right value;
- `null-value` fills missing values with JSON null and uses null for an
  unmatched right value;
- `emit-reject-row` emits row-local source rejections plus one join rejection
  for each otherwise-valid unmatched left row;
- `reject-source-file` emits at most one rejection per source, discards all
  enrichments when either source is rejected, and lets an unmatched valid
  left row reject the right source.

This layer matters because the same malformed source can call for filtering,
imputation, row-level diagnostics, or whole-source rejection. Tests pin a
worked example across all five policies rather than inferring policy behavior
only from implementation agreement.

### 3. Join eligibility and full multiplicity

The join is left-preserving and compares exact nonnull string IDs. Duplicate
keys retain their full Cartesian multiplicity. A source row whose ID was
missing remains nonjoinable even when its displayed replacement is an empty
string or null.

This distinction prevents representation filling from inventing a key. It
also catches implementations that reduce each ID to one dictionary entry and
silently lose duplicate records. The prepared logical expansion is bounded to
1,024 potential enriched rows before output construction.

### 4. Logical intermediate composition

The task semantics round-trip enriched rows through the layout-selected JSONL
or CSV intermediate codec before final JSONL publication. The two trusted
paths frame and parse this stage separately.

The final-state verifier cannot establish that a candidate physically created
an intermediate file or used that codec internally. Therefore the contract
claims only equivalent composition semantics. This observation boundary is
important: a final artifact can prove the relation between inputs and output,
but not the candidate's private operation history.

### 5. Semantic final JSONL

The only permitted final artifact is mode-0644
`output/enriched.jsonl`. It begins with one exact `compose` header and then
contains three closed record kinds:

- enriched rows with `id`, `left`, `right`, and boolean `matched`;
- row rejections with source, zero-based source index, nullable ID, and
  missing fields;
- source rejections with source, reason, affected count, and missing fields.

Rows are ordered by record class and raw UTF-8-aware semantic keys, with null
before text and `matched=false` before `matched=true`. Byte-identical ties are
retained.

The verifier accepts insignificant JSON object-key order and whitespace, then
canonicalizes the parsed objects before comparing them with the trusted
state. It rejects duplicate or unknown keys, wrong exact types, count
disagreement, malformed framing, reordered semantic rows, policy-inconsistent
records, and output over 1 MiB. Semantic acceptance avoids penalizing a
correct serialization while still rejecting an internally inconsistent
answer.

### 6. Generator-backed hostile fixtures

Each cell is instantiated with five public profiles covering spaces and
Unicode, leading dashes and glob characters, empty and duplicate values,
reordered physical input, symbolic-link distractors, missing members,
unmatched records, duplicate join keys, and varied metadata.

The fixtures are distinct authenticated definitions rather than repeated
prompt templates. They matter because parsing and quoting code that succeeds
on one ASCII record often fails on commas, quotes, duplicate keys, empty
fields, or reordered input.

### 7. Two semantic derivations

The primary and reference paths separately parse JSONL and CSV, prepare
policy-specific rows, construct join and rejection events, and round-trip the
intermediate representation. A fixture is admitted only when both paths
produce the same closed semantic state.

The paths intentionally converge on shared datatypes, cryptographic
primitives, and canonical final rendering. Consequently, their agreement is
cross-checking evidence rather than proof of complete implementation
independence. Literal policy tables, parser-boundary tests, output mutations,
workspace mutations, and the reviewed Bash canary cover the shared surface.

### 8. Behavioral discrimination

All 20 cells must have distinct signatures constructed from the two source
byte hashes and the semantic-body hash. The uniqueness check deliberately
excludes task IDs, layout labels, policy labels, and the axis-bearing header,
so parameter names cannot manufacture apparent discrimination.

The frozen discrimination SHA-256 is
`732c1438a4337d2043ee85e2eb4e9e7c437a0051eb1a828cdac6139845db0e94`.
This establishes that the selected public profile produces 20 distinct
observable behaviors; it does not establish sealed difficulty or model
competence.

### 9. Exact workspace verification

The workspace verifier authenticates the task/profile/bundle binding,
reconstructs both trusted semantic paths, validates the materialized baseline,
checks the complete final output semantically, and scans input and output state
before and after verification.

Every input path, kind, byte, mode, mtime, link count, hardlink relation, and
symlink target must remain unchanged. The output directory must be a real
mode-0755 directory containing only one independent link-count-one output
file. Tests cover all 100 task/profile bundles and reject input, symlink
target, output byte, mode, extra-path, and hardlink mutations.

This check still relies on a trusted supervisor for quiescence. Stable scans
narrow a race window; they do not make concurrent untrusted mutation safe.

### 10. Explicit resource proof

The implementation proves a conservative maximum canonical output of 948,427
bytes under its source, scalar, record, and 1,024-row expansion bounds. That
proof deliberately sums enriched and rejection categories even though some
policies make them mutually exclusive, and still remains below the 1-MiB
output limit.

An explicit proof matters because a bounded input does not automatically imply
a bounded join. Duplicate keys can expand quadratically, and escaped JSON
strings can occupy more bytes than their source scalars.

### 11. Fixed reviewed Bash feasibility canary

One fixed Bash program solves all 20 cells and five profiles using a `PATH`
containing exactly `awk`, `jq`, `mkdir`, and `sort`. The test runs in normal
and optimized Python modes, cross-launches the opposite mode, and requires
byte-for-byte equality with each canonical oracle output.

Its frozen identities are:

- Bash literal SHA-256:
  `d196400748ab440a429f49ab41fc7bda3858691a645d97d93d644aa15abc157f`;
- aggregate 100-bundle output/test-vector SHA-256:
  `127db86d96da0d472915c5d2fc41d1fd34c2b316c4cf1c2ce244b14c7eb45a4e`;
- UTF-8 128/129-byte boundary vector:
  `075de603daf44a6d0639a37668f677f00b8d9b98da6773b65209f1a1b9178901`;
- fail-closed parser/process-substitution vector:
  `8bbcac7fb76220085f7d3b314d046894276acd6106f6cc4fca4ea5a8c26fbe24`.

The canary establishes realizability with the declared tools. It does not
admit caller-selected code, provide a production sandbox, or authorize model
scoring.

### 12. Append-only registry and publication

The twelfth registry reconstructs the frozen through-eleventh task prefix once
and rejects task-ID, task-contract, or graph collisions across all 420 tasks.
The catalog reuses that exact task evidence while checking fixture-ID and
fixture-hash uniqueness across all 2,100 bundles. Public publication contains
only hashes, counts, generator identity, verifier identity, output bound, and
explicitly false authority fields—never fixture bytes, paths, prompts, or
oracle answers.

The frozen twelfth identities are:

- family task-set SHA-256:
  `60a8ab6770bae6de43d430db9e3edf136f28f0a0ad2dacfd09b627ce19cf75c3`;
- added registry SHA-256:
  `a9733f220a7bdfb8435841eff875c9fd7b1dbadbee6de2d2aa0646750164f862`;
- cumulative suite SHA-256:
  `32ec82cf193f364946def16462e52217176093d0a3f6399d574c9faf66eaa4a1`;
- cumulative fixture-catalog SHA-256:
  `98cf6ffa48cbe11ece96195450335e5be9a3d0898d54e91396d0c2756171f169`;
- canonical 56,394-byte twelfth manifest SHA-256:
  `792bb1a4116d6698cc07cebfa6edef9c6358ccd4fe497d99703e88ed81262103`.

Coverage v5 and its v4-to-v5 migration append this source commitment, promote
only `jsonl-csv-enrichment-compose`, preserve the prior two promotion records,
and prove the other 24 family declarations unchanged. Their frozen identities
are:

- coverage v5 semantic SHA-256:
  `e5987525654e384c2696908bf147e8224ad3bdc1fb2e0bbc3856a4f23cdca8b9`;
- coverage v5 canonical bytes: 25,241 bytes with SHA-256
  `cfb91bef706fc1c4fd4f95d7891f42e3ec058bbaba28997a22a0f72614d6268f`;
- v4-to-v5 migration semantic SHA-256:
  `7119bbf14ae74047a555483fc7e6e3a9d74ce46cdcb741a13aa5da34a66e1cea`;
- migration canonical bytes: 5,052 bytes with SHA-256
  `f1d4566d17c7b51b3649000f896272ca56ec2f6d32fe5563aa4751c4a6fa563f`.

Those allocation records remain nonauthorizing scope evidence. The next
planned family is `nested-json-schema-migration`.

## What the family does not prove

The verifier observes final output and preserved input state. It cannot prove
physical intermediate materialization, candidate tool use, read scope,
operation order, atomic publication, exit status, transient state, or global
quiescence. Public fixtures cannot measure sealed generalization, and the
reviewed Bash canary cannot establish model quality.

No specialization or compression conclusion follows from this tranche.
Research claims still require admitted training data, backbone feasibility,
the capability-support audit, matched operator and compute controls, protected
capability gates, sealed executable suites, fresh-seed statistics, exact
exports, and deployment measurements defined in `PLAN.md`.
