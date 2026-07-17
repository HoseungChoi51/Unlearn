# Nested JSON schema-migration experiment infrastructure

## What this tranche is for

`nested-json-schema-migration` is the thirteenth executable-static
method-development family. It measures whether one terminal program can
strictly decode versioned nested JSON, apply an exact migration policy, and
publish a complete deterministic document tree.

This family covers a different terminal dependency from Bash-native text
processing. Real maintenance scripts often use Python's standard library for
nested configuration and state migrations. The family therefore exercises the
plan's `python-permitted` track while preserving the same execution-grounded
fixture, oracle, and filesystem requirements as the Bash-native families.

The tranche is public method-development infrastructure. It is not sealed,
scored, eligible for model selection, or evidence of model quality. Its fixed
source-reviewed feasibility program proves only that the declared contract is
realizable with the allowed tools on the tested runtime.

## The 4-by-5 task grid

The input-shape axis is:

- `single-object`: one complete v1 document;
- `object-array`: a nonempty array whose order is retained;
- `keyed-object-map`: a nonempty object map ordered by raw UTF-8 key bytes,
  with every key equal to its value's `record_id`;
- `jsonl-objects`: nonempty, LF-terminated object records whose physical order
  is retained.

The migration-policy axis is:

- `rename-fields`;
- `normalize-types`;
- `lift-nested-members`;
- `drop-deprecated-members`;
- `combined-version-upgrade`.

Their Cartesian product creates 20 task contracts. Five deterministic public
profiles per task create 100 fixture/oracle bundles.

## Components and why each matters

### 1. Strict source framing

Every task reads exactly `input/documents.data`. The source is strict UTF-8,
has no BOM or decoded lone surrogate, ends with LF, and is bounded to 128 KiB.
JSONL forbids blank and CR-framed records. Aggregate shapes contain one JSON
value; duplicate keys are rejected at every nesting level.

The decoder rejects nonfinite values, floating-point values, oversized integer
tokens, excessive depth, excessive object width, excessive node count, and
more than 32 logical documents before those values can enter migration logic.
These checks matter because a permissive JSON loader can silently overwrite a
duplicate member or accept values outside the target schema.

### 2. Closed v1 document schema

A v1 document requires exact integer `schema_version` 1, a nonempty
`record_id`, and a `profile` containing `display_name` and a closed
representation of `enabled`. Optional members are:

- `profile.limits.quota`;
- `profile.contact.email`;
- `profile.deprecated_code`;
- `tags`, as one string or a bounded string array;
- `deprecated.note`.

No other member is accepted. Strings are control-free and at most 128 UTF-8
bytes. `enabled` accepts only booleans, integers 0/1, or the six exact tokens
`true`, `false`, `yes`, `no`, `1`, and `0`. Quotas are bounded exact integers
or canonical decimal strings; string `-0` is noncanonical, and a boolean
cannot pass as an integer. “Control-free” covers Unicode `Cc` and `Cf`
categories, not only ASCII control code points.

A closed schema makes field preservation testable. It also prevents an input
from pre-populating a v2 destination such as `id`, `profile.name`, `email`, or
`quota` and turning migration order into an implicit collision policy.

### 3. Exact policy semantics

Every output document has exact integer `schema_version` 2.

- `rename-fields` moves `record_id` to `id` and
  `profile.display_name` to `profile.name`.
- `normalize-types` converts `enabled` to a boolean, `quota` to an integer,
  and a scalar `tags` value to a one-element array.
- `lift-nested-members` moves `profile.contact.email` to top-level `email`
  and `profile.limits.quota` to top-level `quota`, removing the migrated
  containers.
- `drop-deprecated-members` removes only top-level `deprecated` and
  `profile.deprecated_code`.
- `combined-version-upgrade` applies rename, normalize, lift, and drop in
  that order.

Every other allowed member and value is preserved. Worked-example tests pin
all five transformations independently so agreement between two
implementations cannot define the policy table by itself.

### 4. Deterministic document-set publication

The only permitted output tree is:

```text
output/
├── manifest.json
└── documents/
    ├── 000000.json
    ├── 000001.json
    └── ...
```

Both directories must be real mode-0755 directories. Every file must be an
independent link-count-one mode-0644 regular file. The closed manifest binds
the input shape, migration policy, document count, consecutive filename,
source index, and map key or null.

Array and JSONL documents retain source order. Keyed-map documents use raw
UTF-8 key order. Numbered output names prevent source-controlled keys from
becoming paths. The verifier accepts insignificant JSON whitespace and object
key order, canonicalizes each value, and still requires the exact semantic
tree and physical record order.

Every generated keyed map is physically encoded in a different order from
the required semantic order. The task therefore distinguishes programs that
sort decoded keys from programs that merely preserve source member order.

### 5. Generator-backed hostile profiles

The five profiles cover:

- spaces, Unicode, quotes, and mixed coercible representations;
- leading dashes, globs, brackets, and question marks as literal data;
- empty legal strings and arrays plus duplicate logical document bodies;
- adversarial source ordering and an authenticated symlink distractor;
- a mode-0400 source, a mode-000 distractor, and numeric boundary values.

Each profile activates every primitive migration, so all five policies remain
semantically distinct in every input shape. Distractors are authenticated
inputs that must remain unchanged; they are not additional source discovery
permission.

### 6. Two trusted derivations

The primary derivation mutates a validated private copy in the frozen policy
order. The reference derivation reconstructs the target document member by
member without mutating a v1 copy. A bundle is admitted only when the two
derivations produce the same manifest and migrated document set.

Both paths share strict JSON tokenization, closed validators, canonical JSON,
datatypes, and hashing. Their agreement is therefore cross-checking evidence,
not proof of complete implementation independence. Literal policy tests,
parser boundaries, workspace mutations, and the fixed source-reviewed canary
cover that shared surface.

### 7. Behavioral discrimination

The discrimination signature uses only the selected profile's source bytes
and ordered migrated-document hashes. It excludes task IDs, input-shape and
policy labels, prompts, graph labels, and the axis-bearing manifest.

All 20 task cells have unique observable signatures. The frozen
discrimination SHA-256 is
`416907543c373f36e55098c514fbe17aeef0192d9e5dc43cd025bed809a0ad42`.
This proves public behavioral distinction, not model competence or sealed
difficulty.

### 8. Exact workspace verification

The verifier authenticates the task/profile/bundle relationship, reconstructs
both trusted derivations, validates the materialized baseline, checks every
output document semantically, and rescans both input and output trees.

Every input path, kind, byte, mode, mtime, link count, hardlink relation, and
symlink target must remain unchanged. Missing or extra output files, wrong
directory or file modes, semantic mutations, reordered manifest entries,
symlink outputs, hardlinked outputs, and input mutations fail closed.

Stable scans narrow a race window but do not establish global quiescence. The
verifier still requires a trusted supervisor to keep the workspace quiescent.

### 9. Explicit resource proof

The family permits at most 32 document files. Each document has an 8-KiB
ceiling and the manifest has a 32-KiB ceiling. The implementation reconstructs
escape-heavy maximum-field documents under every policy and a maximum-count
manifest, then reserves the full declared ceiling for every output.

The conservative total is 294,912 bytes, below the shared workspace byte
limit. This proof matters because JSON escaping and collection expansion can
make output larger than the apparent scalar input.

### 10. Fixed Python-permitted feasibility canary

One immutable Bash wrapper invokes an embedded standard-library program with
`python3 -I -S`. Its `PATH` contains exactly `mkdir`, `python3`, and `sort`.
It solves all 100 public bundles, publishes byte-canonical oracle output, and
passes the full workspace verifier in normal and optimized test modes.

Its frozen identities are:

- Bash literal SHA-256:
  `aeba83631e93aa7c22278f1150b5777e0517eb948f73ce6df33094ef1794d48b`;
- Bash literal length: 16,045 UTF-8 bytes;
- aggregate 100-bundle vector:
  `6e1d12e85f6cf904b392f21c64ab3cffb683b5be548198b283cffce65bf6c54d`;
- UTF-8 and source-boundary vector:
  `7f90ebe7b491e3226545fa03ec19c6b04fc4d4a9f0a75d9b3bae0be2cecb4b11`;
- malformed-input and partial-publication failure vector:
  `f36cf44cb7ea7e33901c52726c91f5c30bba71170e201d691031ffcfd784e60e`.

The canary is not an arbitrary-candidate executor. In particular, allowing
`python3` permits broad standard-library and syscall behavior; the declared
tool list is not a Python module or syscall sandbox.

### 11. Append-only registry and publication

The hash-neutral predecessor layer reconstructs the first twelve registries
and catalogs without adding a digest domain. The thirteenth registry appends
20 tasks and rejects task-ID, task-contract, or graph collisions across all
440 tasks. The catalog appends 100 bundles and rejects fixture-ID or
fixture-hash collisions across all 2,200 bundles.

The frozen thirteenth identities are:

- family task-set SHA-256:
  `2ab692e66a3090b5d05a204b18f4fdb99ddc822cdbaa5b7912b7ac2166680e0b`;
- registry SHA-256:
  `01990ca4355ef20736861d7bb7753e09e5ccbbfbddf8d21c4ffce3a451d83873`;
- cumulative suite SHA-256:
  `bb7b78b68879eb32d4849bb5d82cac7a90b0695dc3fa72b9836dd7b6e70863e0`;
- cumulative fixture-catalog SHA-256:
  `25142ebdc014f4d4a53bba34bb9ffeaffa6f87789169180fe0caab69b02fcb9f`;
- canonical 56,396-byte report SHA-256:
  `0250c1e3134d342c57378f0fb8a3b6c4c06ae84ca4fdee4dcda743eefcff8fb7`.

The report contains hashes, counts, generator/verifier identities, and false
authority fields. It contains no fixture bytes, source paths, prompts, or
oracle answers.

### 12. Coverage-v6 promotion proof

[Coverage v6](configs/executable-method-development-coverage-v6.json)
preserves the exact coverage-v5 artifact and changes only the
`nested-json-schema-migration` family from `planned` to `integrated`. Its
[v5-to-v6 migration record](configs/executable-method-development-coverage-v5-to-v6-migration.json)
proves the other 24 family records unchanged,
preserves the first three promotion records, appends exactly the thirteenth
source commitment, and retains the planned axes, Python-permitted track,
allowed tools, filesystem schema, output contract, and capability tags.

The v6 semantic/config-byte SHA-256 values are
`044f026b67a531613b1034b27056f1b6f91e1d95ae8902108428e67a6a9c31cf`
and `e526485ba7b34c0325ff6809dcee428c251cd25dd34e907ca3b2eff56c174d68`
for 25,899 canonical bytes. The v5-to-v6 migration
semantic/config-byte SHA-256 values are
`5c345bc6860f5c9ff70dba656d3cc1204acb705a0d2c4526b4031364313d7e90`
and `31f99bd95165b44cdd5aa4d9bc668b1fcf559a1d621a56c14c80a8d1c5521a8e`
for 5,423 canonical bytes.

This promotion is an allocation-status proof. It does not add human review,
sealing, candidate execution, scoring, model selection, or claim authority.

## Claim boundary

This tranche establishes a deterministic, mutation-tested public development
contract for nested JSON data migration. It does not establish:

- sealed generalization or model performance;
- safety of synthesized or caller-selected programs;
- confinement of Python modules, syscalls, or filesystem reads;
- candidate tool history, exit status, atomicity, or transient behavior;
- global workspace quiescence;
- independent human-review attestation;
- that this family is an adequate proxy for all terminal Python scripting.

Those boundaries remain explicit so later model comparisons cannot treat
benchmark construction evidence as a terminal-performance result.
