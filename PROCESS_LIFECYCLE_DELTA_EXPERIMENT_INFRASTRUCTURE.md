# Process-lifecycle delta experiment infrastructure

## Status and purpose

`process-lifecycle-delta` is the integrated fifteenth executable-static
method-development family. It measures whether one Bash program can compare
two immutable synthetic process snapshots, distinguish process instances from
PID names, and publish a deterministic transition report. Coverage v8
integrates its 20 tasks and leaves one 20-task family planned.

This document was authored to freeze the semantic contract before task
identities were published. It does not itself define task, fixture, registry,
catalog, report, or coverage hashes; the now-frozen identities belong to their
machine-readable artifacts and are recorded below. Any future semantic change
requires new identities rather than reinterpretation of the published ones.

The family is public, unsealed method-development infrastructure. It is not
scored, eligible for checkpoint selection, evidence of model quality, or
authorization to execute a synthesized candidate. A fixed source-reviewed
feasibility program establishes only that the public contract is implementable
on the tested runtime.

## The 4-by-5 task grid

The snapshot-projection axis is:

- `status-only`;
- `status-and-cmdline`;
- `status-and-cgroups`;
- `complete-synthetic-proc`.

The selection-policy axis is:

- `all-changes`;
- `starts-only`;
- `exits-only`;
- `state-changes`;
- `resource-threshold-crossings`.

Their Cartesian product defines 20 task contracts. Five deterministic public
profiles per task produce 100 fixture/oracle bundles.

## Non-negotiable static and safety boundary

Every task operates only on an already materialized workspace. Its process
states are ordinary fixture files. A solution must not:

- inspect live `/proc`, `/sys`, a cgroup filesystem, or host process state;
- invoke `ps`, `pgrep`, `top`, `systemctl`, a container runtime, or a network
  tool;
- start, signal, wait for, renice, trace, or otherwise interact with a
  process;
- use a clock, sleep, poll, or attempt to observe a transition as it happens;
- follow a symlink while discovering or reading a consulted input; or
- modify any input path.

The Bash-native tool budget is exactly Bash built-ins plus `awk`, `comm`,
`jq`, `mkdir`, and `sort`. The task is a static two-state comparison, not a
process supervisor or live-monitoring benchmark.

## Closed workspace layout

The only semantic source root is:

```text
input/process-lifecycle/
├── pair.json
├── before/
│   └── <canonical-pid>/
│       ├── status.json
│       ├── cmdline.json
│       └── cgroups.json
└── after/
    └── <canonical-pid>/
        ├── status.json
        ├── cmdline.json
        └── cgroups.json
```

`pair.json`, `before/`, and `after/` must be real, non-symlink entries.
`before/` and `after/` may be empty. A candidate PID entry is a direct child
whose basename matches `[1-9][0-9]*` and whose numeric value is from 1 through
4,194,304 inclusive. No recursion or alternate process root is permitted.

Names such as `0`, `00`, `07`, `+7`, `-7`, whitespace-padded names, glob
characters, and oversized decimal strings are noncanonical distractors. They
never alias the canonical directory `7`. Other files below the source root
are authenticated distractors, not additional discovery permission.

Every consulted record is an independent regular file whose owner-read bit
`0400` is set. A symlink, directory, device, FIFO, socket, owner-unreadable
file, or other kind at a consulted pathname is not read. Authenticated source
trees containing any hardlink are outside this family domain; hardlinks are
therefore not a candidate-side semantic obligation. Input-tree identity and
the exact output policy are checked after execution by the workspace verifier;
the candidate must preserve every input byte, kind, mode, and symlink target.

## Canonical JSON representation

All valid semantic source documents are canonical UTF-8 JSON over Unicode
scalar values:

- no BOM, invalid UTF-8, decoded lone surrogate, NUL byte, or nonfinite
  number;
- one complete JSON value followed by exactly one LF;
- no duplicate object member at any depth;
- exact closed object members and exact JSON types;
- integer tokens are nonnegative canonical base-10 tokens with no plus sign,
  leading zero, fraction, exponent, or negative form;
- object members use raw UTF-8 key order;
- no insignificant whitespace outside strings;
- non-ASCII scalar characters are encoded directly as UTF-8;
- quotation mark, reverse solidus, and control escapes use the canonical
  JSON spelling; and
- arrays retain their declared semantic order.

The generator and trusted oracle must use one frozen canonical encoder that
implements those rules. Its reference definition is the UTF-8 encoding of:

```python
json.dumps(
    value,
    ensure_ascii=False,
    allow_nan=False,
    sort_keys=True,
    separators=(",", ":"),
) + "\n"
```

after the closed schema and Unicode-scalar checks above. The Python expression
defines source bytes; it does not permit a Bash-native candidate to invoke
Python. A source record that parses to the right value but is not in this
canonical byte representation is malformed. Bounds are checked both before
and after decoding.

This byte-level source rule is deliberate. It gives the Bash-native program a
closed way to reject duplicate members, alternate number spellings, and
permissive-parser normalizations. Candidate output is compared semantically
and does not have to use the oracle's JSON member order or whitespace.

## Pair metadata

`input/process-lifecycle/pair.json` is at most 4 KiB and has the exact semantic
value shown below. The example is pretty-printed for readability; its on-disk
form uses the canonical representation above.

```json
{
  "after": {
    "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
    "snapshot_ticks": 2500
  },
  "before": {
    "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
    "snapshot_ticks": 2000
  },
  "schema_version": 1,
  "thresholds": {
    "cpu_milli_percent": 50000,
    "rss_kib": 4096
  }
}
```

The semantic schema is:

- `schema_version` is the exact integer `1`;
- each `boot_id` is the same lowercase canonical UUID spelling
  `8-4-4-4-12`, using only `[0-9a-f]`;
- `before.snapshot_ticks` and `after.snapshot_ticks` are exact positive
  integers no greater than 9,007,199,254,740,991;
- both boot IDs are equal;
- `before.snapshot_ticks < after.snapshot_ticks`;
- `thresholds.rss_kib` is an exact positive integer no greater than
  9,007,199,254,740,991; and
- `thresholds.cpu_milli_percent` is an exact integer from 1 through 100,000
  inclusive.

The pair builder rejects invalid metadata. Invalid pair metadata is not a
scored task state and has no candidate-output convention.

`cpu_milli_percent` is a synthetic point observation in thousandths of one
percentage point: `100000` means 100.000 percent. It is not cumulative CPU
time and may rise or fall between snapshots. This definition makes both
upward and downward CPU-threshold crossings meaningful without pretending to
decode a kernel-specific `/proc` counter.

## Process status record

Every valid `status.json` is at most 4 KiB and has the exact closed shape shown
below. The example is pretty-printed for readability; its on-disk form uses
the canonical representation above.

```json
{
  "comm": "bash",
  "cpu_milli_percent": 12500,
  "pid": 7,
  "ppid": 1,
  "rss_kib": 2048,
  "start_ticks": 1500,
  "state": "S",
  "uid": 1000
}
```

The exact field rules are:

- `pid`: integer 1 through 4,194,304, equal to the canonical directory
  basename;
- `ppid`: integer 0 through 4,194,304;
- `uid`: integer 0 through 4,294,967,295;
- `start_ticks`: positive integer no greater than
  9,007,199,254,740,991;
- `state`: one exact character in `R`, `S`, `D`, `Z`, `T`, or `I`;
- `rss_kib`: integer 0 through 9,007,199,254,740,991;
- `cpu_milli_percent`: integer 0 through 100,000; and
- `comm`: nonempty scalar Unicode, from 1 through 64 UTF-8 bytes, containing
  no Unicode general-category `Cc` or `Cf` character.

At an endpoint, `start_ticks` must be no greater than that endpoint's
`snapshot_ticks`. A record that claims a future start is not a valid process
observation.

`pid` and `start_ticks` are identity fields. The remaining status fields are
observable mutable fields. The family does not infer identity from `comm`,
arguments, parent, owner, state, resources, or cgroup membership.

## Command-line sidecar

A valid `cmdline.json` is a canonical JSON array and is at most 4 KiB. It
contains from zero through 32 arguments. Each argument:

- is a scalar Unicode string;
- may be empty;
- contains no NUL character;
- occupies at most 128 UTF-8 bytes; and
- contributes to a 512-byte maximum over all decoded argument bytes.

Argument order and duplicates are semantic. Spaces, tabs, LF, CR, quotes,
reverse solidus, leading dashes, glob metacharacters, and non-ASCII scalar
characters are literal data. An empty array is a valid observed empty
command line and is distinct from a missing, unreadable, or malformed
sidecar.

JSON replaces the NUL-framed `cmdline.bin` used by the earlier
`proc-snapshot-report` family. This avoids placing NUL data in Bash variables
and, more importantly, prevents malformed framing from being silently
collapsed into an empty argument vector during a temporal comparison.

## Cgroup sidecar

A valid `cgroups.json` is a canonical JSON array and is at most 4 KiB. It
contains from zero through 32 unique membership paths. Each path:

- is a nonempty scalar Unicode string beginning with `/`;
- contains no NUL, CR, LF, or Unicode general-category `Cf` character;
- occupies at most 128 UTF-8 bytes; and
- contributes to a 512-byte maximum over all decoded path bytes.

The array is strictly ordered by raw UTF-8 path bytes and contains no
duplicates. Equality is therefore set equality over exact path strings.
There is no Unicode normalization, case folding, slash normalization,
dot-segment resolution, hierarchy parsing, controller parsing, or filesystem
lookup.

This is intentionally a bounded synthetic cgroup-membership abstraction. It
does not claim to parse all Linux cgroup v1/v2 line formats or prove that a
path exists on a host.

## Projection axis

A valid process projection always contains the eight status fields:

```text
comm
cpu_milli_percent
pid
ppid
rss_kib
start_ticks
state
uid
```

The selected snapshot axis controls which sidecars are required and exposed:

| Snapshot axis | Required sidecars | Additional projection fields |
|---|---|---|
| `status-only` | none | none |
| `status-and-cmdline` | `cmdline.json` | `argv` |
| `status-and-cgroups` | `cgroups.json` | `cgroups` |
| `complete-synthetic-proc` | both | `argv`, `cgroups` |

For a projection that requires a sidecar, a missing, unreadable, nonregular,
symlinked, malformed, or over-bound sidecar makes that endpoint observation
unknown. For a projection that does not require a sidecar, that pathname is
not consulted and cannot affect validity or comparison. If present, it is an
authenticated distractor that must still be preserved.

Projection member order in output is not semantic. `argv` retains argument
order. `cgroups` retains its canonical raw-byte order.

## Observation states

For each canonical PID basename at each endpoint, discovery produces exactly
one of three states:

- **absent**: there is no filesystem entry with that canonical basename;
- **unknown**: the basename exists but is not a real directory, or a required
  status/sidecar record is missing, unreadable, a symlink, nonregular,
  malformed, inconsistent, or outside a bound; or
- **valid**: the real directory contains one valid status record and every
  sidecar required by the selected projection.

A canonical wrong-kind or unreadable entry is unknown, not absent. A
noncanonical basename is ignored rather than converted to either state for
its apparent numeric value.

The union of canonical PID basenames across both endpoints is compared by
numeric PID. If either endpoint is unknown, that PID is suppressed completely:
it emits no start, exit, change, or threshold event under any policy.
Unknown does not mean empty, zero, stopped, or absent.

The exact endpoint truth table is:

| Before | After | Result |
|---|---|---|
| absent | absent | no event |
| absent | valid | conditional start rule below |
| valid | absent | one `exited` row |
| valid instance A | same valid instance A | compare projected mutable fields |
| valid instance A | different valid instance B | conditional PID-reuse rule below |
| unknown | any state | suppress the PID |
| any state | unknown | suppress the PID |

The generator may include unknown observations as adversarial decoys, but
every profile must also contain valid semantic anchors for every selection
policy. The oracle must derive unknown from raw entries; it must not first
discard malformed records and then compare only the remaining valid set.

## Identity and temporal validity

The conceptual process-instance identity is:

```text
(boot_id, pid, start_ticks)
```

Both snapshots must name the same boot. Within the closed fixture generator,
two generations of one PID are guaranteed not to reuse one `start_ticks`
value. This is a benchmark invariant, not a claim that a truncated real
kernel tick counter is universally collision-proof.

An after-only valid process is `started` only when:

```text
before.snapshot_ticks < after.start_ticks <= after.snapshot_ticks
```

If its `start_ticks` is no later than the before observation, its appearance
cannot be interpreted as a start in a complete snapshot pair. That PID is
suppressed rather than mislabeled.

When both endpoints contain the same PID:

- equal `start_ticks` means the same instance and permits field comparison;
- different `start_ticks` is PID reuse only when the after generation
  satisfies the same strict interval rule above; it emits `exited` for the
  old instance and then `started` for the new instance; and
- a different after generation outside the interval is temporally
  inconsistent and suppresses that PID.

A before-only valid process emits `exited`; no exact exit time is inferred.
The snapshots provide no evidence about how often a PID changed state inside
the interval.

## Projected-field comparison

For the same valid instance, compare every mutable field exposed by the
selected projection using exact JSON value equality. Identity fields `pid`
and `start_ticks` cannot appear in `changed_fields`.

The fixed changed-field order is:

```text
ppid
uid
state
rss_kib
cpu_milli_percent
comm
argv
cgroups
```

Fields absent from the selected projection are skipped. `argv` comparison is
ordered-array equality. `cgroups` comparison is exact equality of the
validated sorted set representation. There is no string normalization,
case folding, numeric tolerance, resource smoothing, path lookup, or
command-line parsing.

If no projected mutable field changes, the instance emits no row. If one or
more fields change, it emits one aggregate `changed` row containing the full
before and after projections and the complete ordered `changed_fields` list.
It does not emit one row per field.

## Threshold crossings

Every event row contains an exact `threshold_crossings` object:

```json
{
  "cpu_milli_percent": null,
  "rss_kib": "upward"
}
```

Each value is exactly `null`, `"upward"`, or `"downward"`. For a same-instance
`changed` row and resource value `x` with threshold `T`:

- upward means `before.x < T` and `after.x >= T`;
- downward means `before.x >= T` and `after.x < T`; and
- every other pair yields `null`.

Consequently, below-to-equal is upward, equal-to-below is downward,
equal-to-equal is not a crossing, and a value change that stays on one side
of the threshold is not a crossing. RSS and CPU are evaluated independently;
one row may cross both in different directions.

`started` and `exited` rows always contain null crossings. Absence and unknown
are never converted to resource value zero. Implementations compare bounded
integers directly and do not subtract values, avoiding overflow and signed
delta ambiguity.

## Aggregate event schema

The only semantic output is `output/transitions.jsonl`. Every row is an exact
closed JSON object with:

```json
{
  "after": {
    "comm": "new",
    "cpu_milli_percent": 51000,
    "pid": 7,
    "ppid": 1,
    "rss_kib": 4096,
    "start_ticks": 1500,
    "state": "R",
    "uid": 1000
  },
  "before": {
    "comm": "old",
    "cpu_milli_percent": 49000,
    "pid": 7,
    "ppid": 1,
    "rss_kib": 3072,
    "start_ticks": 1500,
    "state": "S",
    "uid": 1000
  },
  "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
  "changed_fields": [
    "state",
    "rss_kib",
    "cpu_milli_percent",
    "comm"
  ],
  "event": "changed",
  "pid": 7,
  "start_ticks": 1500,
  "threshold_crossings": {
    "cpu_milli_percent": "upward",
    "rss_kib": "upward"
  }
}
```

The exact top-level members are:

- `boot_id`: the pair's common boot ID;
- `pid`: the event instance's PID;
- `start_ticks`: the event instance's generation;
- `event`: exactly `"started"`, `"exited"`, or `"changed"`;
- `before`: a full selected projection or `null`;
- `after`: a full selected projection or `null`;
- `changed_fields`: an array in the fixed field order; and
- `threshold_crossings`: the exact two-member object above.

Event-specific invariants are:

| Event | `before` | `after` | `changed_fields` | crossings |
|---|---|---|---|---|
| `started` | `null` | full projection | empty | both `null` |
| `exited` | full projection | `null` | empty | both `null` |
| `changed` | full projection | full projection | exact nonempty differences | derived independently |

The top-level `pid` and `start_ticks` must equal every non-null projection's
identity fields. A `changed` row's two projections must have the same
identity. Extra or missing members, alternate event words, boolean-as-integer
values, duplicate JSON members, wrong projection fields, inconsistent
redundant identity, incomplete differences, or fabricated crossings are
malformed output.

## Selection policies

The policy filters complete aggregate rows after all projected fields and
crossings have been derived:

- `all-changes` emits every `started`, `exited`, and `changed` row;
- `starts-only` emits only `started`;
- `exits-only` emits only `exited`;
- `state-changes` emits only `changed` rows whose `changed_fields` contains
  `state`;
- `resource-threshold-crossings` emits only `changed` rows with at least one
  non-null crossing.

A selected row always exposes the full before/after projection, all observed
changed fields, and both resource-crossing results. For example, a
`state-changes` row also reports a simultaneous command-line, owner, RSS, or
cgroup change. The policy must not redact nonselecting fields or manufacture
separate partial events.

## Deterministic row and filesystem order

Rows use this total order:

1. numeric `pid` ascending;
2. event rank `exited`, then `started`, then `changed`; and
3. numeric `start_ticks` ascending as a final tie-breaker.

PID reuse therefore always publishes the old instance's `exited` row
immediately before the new instance's `started` row. This ordering reflects
the reuse constraint. The fixed order of multiple field names within one
`changed` row is serialization only; the snapshots do not reveal a chronology
among field changes.

Rows must be unique under `(boot_id, pid, start_ticks, event)`. The output is
strict UTF-8 JSONL with one JSON value per physical line. A nonempty file ends
in exactly one LF; an empty result is a zero-byte file. Blank lines, CR
framing, trailing material, and repeated rows are invalid.

The complete permitted output tree is:

```text
output/
└── transitions.jsonl
```

`output/` is one real mode-0755 directory. `transitions.jsonl` is an
independent link-count-one mode-0644 regular file bounded to 1 MiB. No other
output path is permitted. JSON object-member order, permitted insignificant
whitespace, and equivalent valid JSON string escaping are not semantic;
physical row order is semantic.

## Resource and complexity bounds

The fixture generator and validator enforce:

- at most 64 canonical PID basenames per endpoint and at most 128 in their
  union;
- at most 8 MiB of total authenticated input-file bytes;
- 4-KiB `pair.json` and `status.json` ceilings;
- 4-KiB ceilings for each consulted sidecar;
- JSON maximum nesting depth 8, maximum object width 32, maximum array length
  32, and maximum 4,096 decoded nodes per document;
- the scalar, string, path, argument, and aggregate-byte bounds above; and
- a 1-MiB output-file and total-output reservation, matching the shared
  descriptor-relative workspace's per-entry ceiling.

Implementation must mechanically construct the largest escaping-heavy
started/exited and changed rows and prove that the maximum event count fits
the 1-MiB output ceiling before integration. The witness uses maximum-width
differing numeric fields and C0 controls whose canonical spelling is the
six-byte `\u00xx` form, not the shorter `\b`, `\t`, `\n`, `\f`, or `\r`
escapes. Its exact 64-process totals are 855,808 bytes for changed rows and
864,704 bytes for disjoint started/exited rows. The 512-byte decoded sidecar
limits are intentionally tighter than the input-file ceiling so that even
worst-case JSON escaping across all endpoint projections remains below that
shared bound. It must test each exact
accept/reject boundary, including 4,194,304/4,194,305 PIDs, safe/unsafe JSON
integers, 64/65 processes, 32/33 sidecar entries, string byte limits, source
file limits, and output limits.

Bounds are checked before converting an untrusted decimal token to Bash
arithmetic. Bash comparisons use explicit base 10; `08` must never be treated
as octal. Values remain at or below 2^53-1 where `jq` and common `awk`
implementations can represent them exactly. The reviewed canary fixes
`LC_ALL=C`, timezone, umask, shell options, tool names, and required feature
probes. A claim-bearing campaign must additionally pin and record exact
runtime tool versions; the public host/CI canary does not pretend that its
ambient binary versions are identical across machines.

## Shell-specific implementation hazards

The feasibility review must explicitly cover:

- numeric PID order (`2`, `10`, `100`), not lexicographic order;
- canonical decimal validation before `10#` Bash arithmetic;
- quoting of spaces, Unicode, newlines, leading dashes, reverse solidus, and
  glob metacharacters;
- no symlink traversal through either a PID directory or a consulted file;
- the fact that `[[ -f path ]]` follows symlinks unless link kind is checked
  separately;
- `comm` requiring already byte-sorted streams under `LC_ALL=C`;
- preserving ordered argument arrays rather than flattening them to strings;
- comparing cgroups as their validated sorted set representation;
- rejecting duplicate JSON members and permissive numeric spellings even if
  `jq` would normalize them;
- avoiding command substitution or word splitting that loses empty values,
  LF data, or trailing framing;
- pipeline status and temporary-output cleanup; and
- producing the exact final file on empty and nonempty result paths.

`comm` may assist with already validated ASCII instance keys. It is not a
JSON, Unicode, cgroup, or command-line parser. A fixed canary must demonstrate
the complete behavior with only the declared external commands available in
`PATH`.

## Required public fixture coverage

Every one of the five profiles must contain enough valid anchors that all five
selection policies produce a nonempty result. Across each profile there must
be at least:

- one valid start in the strict observation interval;
- one valid exit;
- one same-instance state change;
- one RSS and one CPU threshold crossing, including at least one row that
  changes additional nonselecting fields;
- one unchanged same instance that emits nothing;
- one unknown observation paired with a valid or absent endpoint that emits
  nothing; and
- one PID reuse that emits exactly exit then start.

The profiles additionally have these obligations:

### `spaces-unicode`

Exercise spaces and non-ASCII scalar values in `comm`, arguments, and cgroup
paths; empty and duplicate argv values; literal quote and reverse-solidus
data; simultaneous changes; and independent RSS/CPU directions.

### `leading-dashes-globs`

Exercise arguments and cgroup paths beginning with dashes and containing
`*`, `?`, and bracket expressions. Include PID-like noncanonical names and
ensure no source-controlled string becomes an option, glob, or path lookup.

### `empty-duplicates`

Exercise valid empty argv/cgroup arrays, empty ignored directories, duplicate
argv entries, malformed duplicate cgroup entries, duplicate JSON members,
duplicate mutable process projections under different PIDs, exact-threshold
noncrossings, and completely empty before/after snapshots plus zero-byte
output in a separate derived test.

### `symlinks-ordering`

Physically shuffle source entries, include PIDs `2`, `10`, and `100`, place
symlinks at exact consulted basenames and at PID-directory names, include
nonconsulted symlink distractors, exercise PID reuse, and prove numeric/event
ordering. Do not generate hardlink distractors: any authenticated hardlink is
outside the family domain, and the family does not grant `stat` for semantic
hardlink policy.

### `partial-permissions`

Exercise owner-readable (`0400`) boundaries, unreadable status and sidecars,
missing/malformed required records, valid nonrequired malformed sidecars,
PID/status mismatch, a future start, an after-only process born at or before
the before tick, threshold equality on both sides, minimum and maximum valid
numeric values, and over-bound decoys. Unknown cases must never become false
starts, exits, empty command lines, or zero-resource crossings.

Every snapshot-projection cell must be behaviorally distinguishable without
using task IDs or axis labels. In particular, fixtures must make argv and
cgroup projections observably different rather than relying on a changed
task hash. A label-free discrimination signature may use authenticated source
bytes and semantic transition content, but must exclude task IDs, prompt
labels, graph labels, and echoed axis labels.

## Literal worked examples required before generation

Hand-authored expected vectors must pin at least:

- identical snapshot states produce no row;
- absent to valid inside the interval produces one `started` row;
- valid to absent produces one `exited` row;
- after-only with `start_ticks == before.snapshot_ticks` is suppressed;
- after-only with a start before the before snapshot is suppressed;
- same PID and generation with state-only change produces one aggregate row;
- same instance with several changes produces one row and exact field order;
- same PID with a new valid generation produces exit then start;
- a generation that moves backward or is born outside the interval is
  suppressed;
- an unknown endpoint never becomes start or exit;
- below-to-equal and equal-to-below threshold boundaries;
- a resource value change without a crossing;
- simultaneous RSS-up and CPU-down crossings;
- command-line order, duplicate arguments, and empty arguments;
- cgroup source reorder is rejected as noncanonical, while two equal
  canonical sets compare equal; and
- numeric PIDs sort `2`, `10`, `100`.

These vectors are written independently of the generator. Agreement between
two implementations cannot define the intended truth table by itself.

## Independent oracle requirements

The primary and reference derivations must each consume raw immutable fixture
entries. Neither may consume the other's parsed process map, normalized
observation records, identity join, changed-field list, threshold result, or
event rows.

A suitable independence split is:

- the primary path indexes each endpoint by canonical PID, classifies
  observations, joins the union, and emits aggregate transitions; while
- the reference path rescans raw endpoint entries for each numeric PID,
  reconstructs projections independently, and applies a separately written
  truth table and ordering key.

Tests must monkeypatch primary-only discovery, identity, comparison,
threshold, and serialization helpers to fail while the reference derivation
still succeeds. The two paths may share immutable datatype definitions,
canonical JSON primitives, hashing, and workspace input types only when that
shared surface is disclosed. Shared use of one JSON library is not evidence
that observation semantics are correct; literal vectors, parser-boundary
tests, randomized differential tests, and mutations must cover that common
surface.

The implementation-session differential audit must generate bounded random
pairs across all 20 cells, including PID reuse, unknown states, all threshold
relations, empty projections, and simultaneous changes. It records the seed
and aggregate vector but does not create model-selection evidence.

## Semantic and workspace verifier requirements

The family uses a distinct semantic-verifier identity. The existing
`proc-snapshot-report` verifier requires one strictly increasing row per PID
and cannot represent PID reuse; it must not be reused.

The new parser independently validates:

- strict UTF-8 JSONL framing and duplicate-member rejection;
- the exact event union schema and full projection selected by the task;
- exact integers rather than booleans, floats, exponents, or unsafe values;
- redundant top-level/projection identity consistency;
- null placement for started and exited rows;
- complete `changed_fields` and threshold objects;
- row uniqueness and numeric PID/event/generation order; and
- empty-file semantics.

Semantic comparison canonicalizes each valid row but preserves physical row
order. The workspace verifier separately requires the exact output tree,
mode, regular-file kind, link count, byte ceiling, input preservation, and
stable post-read rescans.

Repeated scans narrow a mutation window but do not prove global quiescence,
candidate exit status, transient filesystem atomicity, read scope, command
history, or tool use. Those properties require the separate trusted
supervisor and reviewed-program execution path. This public family does not
authorize arbitrary candidate execution.

## Fixed source-reviewed Bash feasibility canary

The integrated tranche contains one immutable source-reviewed Bash program
that solves all 100 public bundles using only Bash built-ins and a restricted
`PATH` containing exactly `awk`, `comm`, `jq`, `mkdir`, and `sort`.

The checked-in canary satisfies these locked requirements:

- agree semantically and byte-canonically with both trusted derivations;
- pass the full workspace verifier for every bundle;
- preserve every input entry;
- pass under the normal and optimized test suites with assertions disabled;
- demonstrate that removing any required external command fails closed;
- prove that it never reads live `/proc` or starts, signals, waits for, or
  polls a process;
- carry a fixed literal hash, literal byte length, 100-bundle aggregate
  vector, exact-boundary vector, and malformed/partial-publication vector;
  and
- retain explicitly false candidate-execution, model-selection, claim, and
  independent-human-review authority fields.

This is feasibility evidence for one reviewed literal, not permission to run
a model-generated program and not evidence that a model can solve the family.

The fixed literal and its 100-bundle aggregate, exact-boundary, and
malformed/fail-closed vectors are published as
`reviewed lifecycle Bash literal`, `lifecycle canary aggregate vector`,
`lifecycle canary boundary vector`, and `lifecycle canary failure vector` in the
[artifact identity ledger](ARTIFACT_IDENTITY_LEDGER.md#fifteenth-tranche-and-coverage-v8).

## Mandatory mutation and metamorphic evidence

At minimum, tests must kill these plausible faults:

### Identity and time

- join only by PID or only by `start_ticks`;
- omit `boot_id` from conceptual identity;
- accept different boot IDs;
- collapse PID reuse into one `changed` row;
- emit start before exit for reused PID;
- accept a future or backwards generation;
- treat an old after-only generation as a start; and
- parse an overlong decimal before applying its bound.

### Observation classification

- convert malformed, missing, unreadable, symlinked, or wrong-kind status to
  absence;
- collapse malformed/missing cmdline to `[]`;
- collapse malformed/missing cgroups to `[]`;
- let a nonrequired sidecar affect a projection;
- follow a symlink PID directory or exact sidecar;
- accept a PID/status mismatch; and
- last-wins duplicate logical records or JSON members.

### Field and threshold semantics

- compare argv as a flattened string or unordered set;
- compare cgroups in source order without canonical validation;
- omit one simultaneous changed field;
- include identity fields in `changed_fields`;
- use `>` instead of `>=` at either threshold boundary;
- treat start or exit as a crossing from or to zero;
- report only the policy-selecting change instead of the full row; and
- overflow or lose precision near the maximum safe integer.

### Ordering, JSON, and workspace

- lexicographic PID sort;
- wrong event rank or duplicate event row;
- missing final LF, blank line, CR framing, or trailing bytes;
- extra/missing row or object member;
- bool, float, exponent, negative zero, nonfinite value, unsafe integer, or
  duplicate-key acceptance;
- alternate projection shape;
- extra output path, wrong mode, symlink output, or hardlinked output; and
- any input-byte, mode, kind, link, or symlink-target mutation.

Required metamorphic properties include:

- comparing a valid state with itself emits no row;
- permuting physical input-entry order does not change semantics;
- adding a noncanonical distractor does not change semantics;
- adding or mutating a nonrequired sidecar does not change a projection;
- changing one required valid sidecar to unknown suppresses that PID rather
  than creating a delta;
- cgroup set equality is invariant under construction order before canonical
  encoding;
- every selected-policy result is an order-preserving subset of the
  `all-changes` result for the same projection and fixture; and
- changing only one resource across its boundary changes exactly its crossing
  result and the resource-policy subset.

## Publication gates and assurance limits

The family was published as a public method-development tranche only after all
of the following existed and agreed:

1. the exact 20-task registry and five-profile/100-bundle fixture grid;
2. deterministic regeneration with unique descriptors and authenticated
   input, oracle, and output-policy identities;
3. primary/reference raw-input agreement on all bundles;
4. literal worked examples and parser-boundary tests;
5. recorded randomized and metamorphic differential audits;
6. the complete mutation matrix above;
7. materialization and semantic/workspace verification of all bundles;
8. label-free behavioral discrimination of all 20 cells;
9. the fixed reviewed Bash canary over all 100 bundles under the exact tool
   budget;
10. exact resource-bound proofs and normal/optimized test-suite parity;
11. append-only task registry, cumulative suite, catalog, and canonical
    report construction;
12. a one-step backward-linked coverage migration that changes only this
    family's lifecycle state and integrated task-set identity; and
13. an explicit report that the tranche remains public, unsealed, unscored,
    nonauthorizing, and not independently human-reviewed unless a real review
    has separately been recorded.

The frozen semantic and file identities are published as the
fifteenth-tranche entries in the
[artifact identity ledger](ARTIFACT_IDENTITY_LEDGER.md#fifteenth-tranche-and-coverage-v8).
The [coverage-v8 lock](configs/executable-method-development-coverage-v8.json)
has the stable semantic and exact-file names `coverage v8` and
`coverage v8 config file`. The
[v7-to-v8 migration](configs/executable-method-development-coverage-v7-to-v8-migration.json)
has the stable semantic and exact-file names `coverage v7-to-v8 migration`
and `coverage v7-to-v8 migration config file`. Both artifacts retain false
scoring, candidate-execution, model-selection, and claim authority; coverage
v8 and the report also record that independent human review is not attested.

Even after those gates, the evidence establishes correctness only for bounded
static synthetic pairs. Two snapshots cannot reveal intermediate state
changes, exact start or exit times, resource trajectories, causal order among
field changes, observation races, PID reuse outside the closed generation
invariant, or real cgroup-kernel semantics. Unknown observations are
deliberately suppressed and can hide a real event. The fixture's boot ID and
snapshot ticks are trusted input data, not measurements.

The family therefore supports method-development coverage of temporal diff,
structured process state, resource thresholds, quoting, and Unix concepts. It
must not be cited as evidence of live process-monitor safety, supervisor
correctness, host isolation, or general Linux observability.
