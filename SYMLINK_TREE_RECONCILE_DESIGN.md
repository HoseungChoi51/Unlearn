# Symlink-aware tree reconciliation: prospective design

## Status and scope

This is the reviewed design contract for the final public
method-development family, `symlink-aware-tree-reconcile`. It is prospective:
no task, fixture, catalog, coverage-promotion, or report identity is frozen by
this file, and no candidate execution, scoring, model selection, sealing, or
claim authority follows from it.

The predecessor is Git commit `0d0fbf4` and its `coverage v8` artifact. The
coverage-v8 record remains immutable historical planning evidence. This design
keeps its family ID, axes, filesystem/output identities, capability tags,
task count, and Bash-native track, but corrects the planned external-tool
budget as described below. Any eventual coverage promotion must expose that
change explicitly rather than pretending the v8 declaration was preserved.

## Frozen allocation retained

The family remains the Cartesian product of:

- `desired_state_format`: `jsonl`, `csv`, `nul-records`, or
  `directory-blueprint`;
- `reconciliation_policy`: `create-missing`, `replace-mismatch`,
  `remove-extra`, `preserve-safe-links`, or `strict-exact-state`.

The first axis is major and the second is minor, producing exactly 20 task
contracts in that order. The retained allocation fields are:

| Field | Retained value |
|---|---|
| Family ID | `symlink-aware-tree-reconcile` |
| Solution track | `bash-native` |
| Filesystem identity | `actual-and-desired-filesystem-trees` |
| Output identity | `reconciled-tree-and-operation-log` |
| Capability tags | `filesystem-mutation`, `state-reconciliation`, `symlinks`, `tree-operations` |

Every task must have a distinct contract and normalized graph. The decoder
node distinguishes the four formats; the policy node distinguishes the five
state transforms.

## Design correction: external tools

Coverage v8 planned only:

`chmod`, `find`, `ln`, `mkdir`, `mv`, `sort`, and `stat`.

That set is insufficient for the intended task:

- a bespoke Bash substring parser is not credible JSONL support;
- the set has no robust CSV field processor;
- Bash variables cannot preserve arbitrary file bytes containing NUL;
- state comparison and copy-on-write output need byte comparison and copying.

The corrected exact sorted tuple is:

`awk`, `chmod`, `cmp`, `cp`, `find`, `jq`, `ln`, `mkdir`, `mv`, `sort`,
and `stat`.

The four additions are narrowly justified:

- `awk` parses the fixed single-record-line CSV subset;
- `cmp` compares regular-file payloads without loading them into shell
  variables;
- `cp` copies arbitrary bounded regular-file bytes without following a
  symlink;
- `jq` parses and validates JSONL objects.

`rm`, `rmdir`, `readlink`, Python, Perl, compilers, and network tools remain
disallowed. Literal link targets are obtained with no-follow `find` output.
Removal is a logical omission from a fresh output tree, not an in-place
deletion.

## Copy-on-write workspace contract

The candidate treats all of `input/` as immutable and constructs a new state:

```text
input/
├── actual/                    # current no-follow leaf state; may be absent
├── desired.jsonl              # exactly one representation is present
├── desired.csv
├── desired.nul
├── desired-blueprint/
└── desired-payloads/          # payload IDs used by record formats

output/
├── tree/                      # reconciled final state, always a real dir
└── operations.tsv             # canonical decision record
```

Only the representation selected by the task is present. A missing
`input/actual/` or `input/desired-blueprint/` denotes an empty tree.
Record-format payload files are metadata inputs and are not members of the
desired tree.

The candidate must preserve every input path, kind, byte, mode, modification
time, hard-link count, and literal symlink target. It must leave no output
other than the real mode-0755 `output/` and `output/tree/` directories, the
reconciled tree below `output/tree/`, and an independent mode-0644,
link-count-one `output/operations.tsv`.

This is final-state, copy-on-write reconciliation. It does not claim to
observe destructive in-place behavior, syscall order, staging, atomicity,
rollback, crash recovery, tool history, read history, or candidate exit
status.

## Logical tree model

The semantic state is a map from canonical relative leaf paths to one of:

- `file(mode, bytes)`;
- `symlink(literal_target)`.

Directories are implicit ancestors:

- every directory is a real mode-0755 directory;
- every non-root directory has at least one leaf descendant;
- empty directories and non-0755 directory modes are outside this family;
- no leaf may be an ancestor of another leaf.

Regular files are independent names. Input or output hard-link topology is
not semantic in this family, and every output regular file must have link
count one. File bytes may be arbitrary, including NUL, subject to the resource
bounds below.

Paths are strict UTF-8 and canonical relative POSIX paths. They may contain
spaces, Unicode, leading dashes, and shell glob characters, but not ASCII
control characters, DEL, comma, double quote, or backslash. Components are
neither empty nor `.` nor `..`.

Symlink targets are observed literally and never followed. A target is strict
UTF-8, relative, canonical, contains no parent component, and satisfies the
same control/delimiter exclusions. A canonical target may still be dangling,
name another symlink, or participate in a cycle; those cases are not
automatically “safe.”

Two leaves match exactly when:

- both are regular files with identical bytes and permission mode; or
- both are symlinks with the same literal target.

Modification time, ownership, device/inode number, ACLs, xattrs, sparse
layout, and filesystem-specific link resolution are not part of semantic
equality.

## Desired-state grammars

All four formats decode to the same immutable leaf map. Exact duplicate
records collapse. Two records for the same path that differ in any field are
invalid. Every parser rejects malformed framing, duplicate JSON members,
noncanonical modes or paths, ancestor conflicts, unknown fields/kinds,
unbounded input, and missing payload references.

### JSONL

`input/desired.jsonl` is UTF-8 JSON Lines. Each nonempty physical line is one
object with exactly four members:

```json
{"kind":"file","mode":"0644","path":"docs/a.txt","value":"payload-01"}
{"kind":"symlink","mode":null,"path":"current","value":"docs/a.txt"}
```

Objects may use any member order. `kind` is `file` or `symlink`. File `mode`
is a four-digit octal string and `value` is a canonical payload ID. Symlink
`mode` is JSON null and `value` is the literal target. Empty desired state is
a zero-byte file.

### CSV

`input/desired.csv` is the canonical single-line-record RFC 4180 subset:

```text
kind,mode,path,value
file,0644,docs/a.txt,payload-01
symlink,,current,docs/a.txt
```

The exact header is required. Fields cannot contain comma, quote, CR, LF, or
NUL, so quoting is neither needed nor accepted. The file ends in LF. Header
only denotes an empty desired state.

### NUL records

`input/desired.nul` is a sequence of four-field records:

```text
kind NUL mode NUL path NUL value NUL
```

File and symlink field meanings match CSV. The final field must be
NUL-terminated; truncation and partial records are invalid. Zero bytes denotes
an empty desired state.

### Directory blueprint

`input/desired-blueprint/` directly represents the desired leaves. Regular
file bytes and modes are authoritative. Symlink targets are read literally
without following them. All discovered directories must be real mode-0755
directories and satisfy the implicit-directory rules. An absent root denotes
an empty desired state.

### Cross-format equivalence

Matched fixtures encode the same logical desired state in all four formats.
For a fixed actual state and policy, their final tree and
`operations.tsv` must be byte-identical. This equivalence is intentional:
the format axis measures decoder competence and must not be made artificially
“discriminable” by changing the semantic answer.

## Reconciliation policies

Let:

- `M` be a desired leaf missing from actual;
- `X` be a present leaf that does not exactly match desired;
- `E` be an actual leaf absent from desired;
- `A` be the special safe-link alias defined below.

The action table is frozen prospectively as:

| Policy | Missing `M` | Mismatch `X` | Extra `E` | Safe alias `A` |
|---|---|---|---|---|
| `create-missing` | create | defer | retain | defer |
| `replace-mismatch` | defer | replace | retain | replace |
| `remove-extra` | defer | defer | remove | defer |
| `preserve-safe-links` | create | replace | remove | preserve |
| `strict-exact-state` | create | replace | remove | replace |

An exact existing match is kept under every policy.

The first three policies deliberately perform one action class only; their
final trees may not equal the desired tree. `preserve-safe-links` and
`strict-exact-state` are complete reconciliation policies.

### Safe-link alias

An actual symlink at desired path `P` is a safe-link alias only when all of
these conditions hold:

1. desired `P` is a regular file;
2. the literal target is canonical, relative, and has no parent component;
3. resolving that target lexically from `P`'s parent yields desired path `Q`
   within the tree;
4. desired `Q` is a regular file, not a symlink;
5. desired files `P` and `Q` have identical bytes and modes.

The check is one hop and map-based. It never opens through the actual link.
Dangling targets, directory targets, link-to-link chains, cycles, undeclared
targets, mode/content differences, and lexical escape attempts are not safe.

`preserve-safe-links` recreates the actual literal link at `P`.
`strict-exact-state` creates the desired regular file at `P`.
Extra links absent from desired are removed by both complete policies.

## Canonical decision log

`output/operations.tsv` is a declarative final-state decision record, not a
trace of syscalls that occurred. It has the exact header:

```text
path	decision	actual_kind	desired_kind	final_kind
```

There is one row for every raw-byte-sorted path in the union of actual and
desired leaves. Allowed decisions are:

- `keep`;
- `create`;
- `replace`;
- `remove`;
- `preserve-safe-link`;
- `defer-missing`;
- `defer-mismatch`;
- `retain-extra`.

Kinds are `absent`, `file`, or `symlink`. Fields cannot contain tab, CR, LF,
or NUL. The final row ends in LF; the header is present even for an empty
union.

The log makes the partial-policy behavior observable, but the verifier must
derive it independently from input state. A self-consistent log cannot
substitute for checking the complete output tree.

## Public fixture obligations

Each of the 20 tasks receives the repository's five ordered public profiles,
for 100 bundles:

1. `spaces-unicode` uses space-bearing and non-ASCII paths and targets.
2. `leading-dashes-globs` uses leading dashes and literal `*`, `?`, and
   bracket characters.
3. `empty-duplicates` covers empty actual or desired state, empty files,
   exact duplicate records, and repeated payload bytes.
4. `symlinks-ordering` reverses physical record order and includes a safe
   alias, dangling link, link chain, and cycle without following any link.
5. `partial-permissions` covers mode-000 empty leaves, owner-readable payloads
   with varied modes, and permission-bit mismatch.

Every profile contains the common `M`, `X`, `E`, `A`, and exact-match policy
probe. Therefore the five policy outcomes must be distinct in every profile.
The four formats for a matched profile/policy must remain semantically
equivalent.

The family does not cover effective-user access races, inaccessible
directories, ACL denial, mount boundaries, device files, sockets, FIFOs, or
external symlink targets. The profile name `partial-permissions` refers to
permission-bit state, not a claim that every kernel access failure is modeled.

## Independent semantic paths

The production primary and reference implementations both start from raw
fixture inputs.

The primary path may:

- decode into dictionaries keyed by path;
- calculate equality and safe aliases by direct lookup;
- apply the policy table;
- serialize the final state and decision rows.

The reference path must instead:

- use separate format-specific tokenizers;
- normalize independently into byte-sorted entry streams;
- merge actual and desired streams without primary map/planner helpers;
- classify safe aliases from literal path components without following links;
- derive decisions and final entries through a separate transition table;
- serialize with a separate row builder.

Only closed immutable value types, resource constants, and domain-separated
hash primitives may be shared. Tests must monkeypatch every primary
parser/planner/equality/safe-link/log helper while the reference path still
succeeds. Forced primary/reference disagreement must fail closed.

A third test-only derivation must inspect raw fixture definitions directly and
agree across all 100 bundles.

## Verifier and mutation requirements

The family needs a custom bundle/oracle/verifier because the generic bundle
intentionally rejects expected symlink outputs. The generic workspace's
descriptor-relative materializer, stable no-follow scans, bounded regular-file
egress, literal symlink-target egress, and input-object-identity check should
be reused without widening first-tranche V1 invocation.

The verifier must:

- reconstruct the exact expected final leaf map and decision log;
- require real mode-0755 `output/` and `output/tree/` directories;
- reject every missing, extra, wrong-kind, wrong-mode, wrong-byte, hardlinked,
  or wrong-target output;
- read regular files without following any path component;
- read each literal symlink target through bounded no-follow egress;
- require every output regular file to have link count one and no link to an
  input inode;
- prove exact input portable state and process-local object identity remained
  unchanged;
- bracket all egress with stable input and output rescans.

Required mutant classes include:

- JSON duplicate member, unknown member, bad escape, nonobject, blank line,
  and truncation;
- CSV wrong header, delimiter, quoting, CR, extra field, and missing final LF;
- NUL missing terminator, partial record, extra field, and embedded empty
  required field;
- conflicting duplicate path, unsafe path, ancestor conflict, bad mode,
  missing payload, oversized input, and wrong blueprint object kind;
- format collapse or physical-order dependence;
- missing/create, mismatch/replace, extra/remove, or complete-policy collapse;
- following a link, resolving more than one hop, preserving dangling/chained/
  cyclic/directory/unequal aliases, or failing to preserve the exact safe
  alias;
- wrong raw-byte row order, decision, kind, header, final LF, or extra log row;
- missing/extra output, symlink/file substitution, wrong target, wrong bytes
  or mode, output hardlink, output-to-input hardlink, and symlinked ancestor;
- input byte/mode/mtime/target/link-count mutation or byte-identical inode
  replacement;
- stale scan, cross-workspace handle, forged task/graph/fixture/oracle/type,
  authority escalation, and primary/reference disagreement.

All core, custom-verifier, materialization, canary, registry, catalog, report,
coverage, and migration tests must pass in normal and optimized Python.

## Resource bounds

The prospective family limits are:

- at most 96 actual leaves;
- at most 96 unique desired leaves after exact-duplicate collapse;
- at most 64 record-format payload files;
- at most 512 UTF-8 bytes per relative path and 128 per component;
- at most 12 path components;
- at most 16 KiB per regular file;
- at most 1 MiB of actual plus desired regular-file payload bytes;
- at most 192 final leaves;
- at most 1 MiB of final regular-file bytes;
- at most 256 KiB for `operations.tsv`;
- at most 2 MiB for the complete output tree.

Implementation must provide mechanical worst-case witnesses for every derived
output/log bound rather than relying on typical fixtures.

## Bash feasibility gate

Before any family identity is frozen, one fixed source-reviewed Bash literal
must solve all 100 public bundles under an isolated `PATH` containing exactly
the corrected tool tuple.

The canary must:

- use `jq` only for JSONL and `awk` only for CSV;
- parse NUL records with Bash built-ins;
- discover blueprints and actual state with no-follow `find`;
- compare and copy file payloads with `cmp` and `cp` without loading arbitrary
  bytes into variables;
- obtain literal targets without opening through links;
- construct a fresh staged tree, create links with `ln`, apply file modes with
  `chmod`, sort deterministically, and publish with `mv`;
- preserve all inputs and fail when any required external command is absent.

Its source and test-vector identities belong only in the artifact identity
ledger after review. The canary is feasibility evidence for one literal, not
permission to run generated code and not evidence that a model solves the
family.

## Publication and review sequence

Implementation remains split into reviewed branches:

1. close this corrected design and tool-budget decision;
2. implement the family-local types, codecs, semantic engines, fixtures, and
   custom verifier without publishing identities;
3. run mutation, equivalence, discrimination, resource, and Bash-canary gates;
4. independently review all 500 public-development tasks and 2,500 bundles;
5. only after that review, append the sixteenth registry/catalog/report and a
   backward-linked coverage promotion that exposes the v8 tool correction;
6. review the complete Gate 1 evidence and decide whether to `merge`,
   `modify`, or `stop` before Gate 2.

No step may relabel public development data as sealed or scored evidence.
