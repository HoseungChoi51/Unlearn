# Hardlink experiment infrastructure

## What this tranche is for

`hardlink-deduplicated-mirror` is the ninth executable-static development
family. It tests whether a model can synthesize a Bash program whose
correctness depends on both ordinary file contents and physical filesystem
topology. The task is useful for terminal specialization because a plausible
textual answer is insufficient: files that should be deduplicated must really
share an inode, while unrelated names must not.

This tranche is benchmark infrastructure, not a model result. Everything is
public method-development data. It is unsealed, unscored, and ineligible for
model selection or research claims.

## Why the coverage grid changed

The v1 coverage plan proposed four equivalence keys and five link policies.
Implementation review found three problems:

- `sha256` and `size-and-sha256` cannot differ unless SHA-256 itself collides,
  so they do not form two empirically distinguishable task cells.
- `first-discovered-owner` is nondeterministic unless discovery order is made
  part of the contract.
- several proposed link policies mixed grouping, filtering, and owner
  selection, producing nonorthogonal or redundant cells.

The v1 artifact remains immutable historical evidence. The backward-linked v2
coverage record replaces only this family with a discriminable grid:

- equivalence key: `sha256`, `mode-and-sha256`,
  `suffix-and-sha256`, or `declared-group-and-sha256`;
- owner policy: smallest path, largest path, oldest mtime, newest mtime, or
  manifest priority.

A four-file partition probe distinguishes all four equivalence keys. A
five-file owner probe makes every owner policy select a different
representative. The resulting 20 fixture-oracle-derived signatures are all
unique; separate materialization and Bash-canary tests exercise real
workspaces.
The other 24 family records are unchanged across the v1-to-v2 migration.

## Components and why each matters

### 1. Task contract and registry

The family module defines the exact prompt, semantic graph, allowed tools,
4-by-5 parameter order, output contract, and explicit observation limits.
The ninth registry binds the 20 task contracts to the frozen first eight
tranches and rejects task, graph, or contract-hash collisions across all 360
tasks.

This layer matters because experiment comparisons are meaningless if two
nominal cells have the same behavior, if task order drifts between runs, or if
a later edit silently changes a prompt.

### 2. Generator-backed hostile fixtures

Every task has five public profiles, for 100 new bundles. Fixtures cover
spaces and Unicode, leading dashes and glob characters, empty files,
pre-existing hardlinks, symlink distractors, reversed manifest order, and
different permission modes. Source mtimes are committed explicitly.

Two special cohorts make the grid testable:

- the partition cohort has identical bytes but mode, suffix, and declared
  group assignments that yield four different partitions;
- the owner cohort has identical grouping attributes but path, mtime, and
  priority assignments that yield five different owners.

Hostile fixtures matter because a happy-path copy script can look correct
while mishandling quoting, aliases, metadata, or filesystem object kinds.

### 3. Separately structured parsing and grouping engines

The primary oracle partitions records with a dictionary. The reference oracle
sorts and groups an independently parsed source stream. Bundle construction
requires both paths to produce the same source groups before they enter a
shared final-state assembler. That assembler applies the common owner-selection
policy and constructs the member records, output bytes and metadata, topology
commitments, and ledger.

The separation therefore provides an independent check of source parsing and
partition formation, but it is not a fully independent implementation of the
downstream state semantics. Assurance for the shared assembly logic comes from
the partition and owner discrimination probes, mutation tests, and verification
against materialized workspaces.

### 4. Hardlink-aware workspace model

The generic workspace layer now supports:

- input hardlink aliases with a canonical regular-file anchor;
- exact committed whole-second input mtimes;
- portable hardlink-group digests derived from visible paths and link count;
- output policies that can defer link-count checks to a topology-aware family
  verifier;
- answer-free expected symlink declarations and race-resistant symlink
  egress.

Raw device and inode numbers are retained only inside the trusted
process-local workspace handle and never serialized. Portable records bind the
visible group instead; the family additionally compares the live local object
identities with the materialized baseline so byte-identical inode replacement
does not pass as unchanged input.

This layer matters because byte equality does not prove deduplication.
Conversely, serializing host-specific inode numbers would make fixtures
nonreproducible.

### 5. Private oracle and exact final-state verifier

The private oracle commits every output file's bytes, mode, mtime, required
link count, and portable hardlink-group digest. It also commits the exact
ledger:

- aggregate candidate, group, and saved-inode counts;
- one byte-sorted row per source;
- selected owner, semantic group digest, and group size.

The workspace verifier checks the whole allowed output tree, reads files
without following links, compares physical topology, and rescans inputs and
outputs to detect mutation during verification.

This is the main functional scoring boundary for the family. It prevents
false passes from copied-but-not-linked files, over-linked files, links to an
external inode, wrong metadata, extra paths, or changed inputs.

### 6. Linear predecessor evidence and fixture catalog

Historical tranche builders recursively reconstructed earlier tranches. The
linear evidence layer instead builds each first-through-eighth task tranche
and catalog once, verifies every frozen hash, then performs one global
identity pass. The ninth catalog adds 100 bundles to the 1,700 frozen
predecessors for 1,800 cumulative fixtures.

This matters operationally because recursive reconstruction becomes expensive
as families accumulate. It also matters scientifically: the optimized path is
hash-neutral and proves it has not weakened predecessor admission.

### 7. Fixed reviewed Bash canary

A hand-authored Bash literal solves every one of the 100 new public fixtures
under a restricted `PATH`. Its external commands are exactly:

`cp`, `find`, `ln`, `mkdir`, `sha256sum`, `sort`, and `stat`.

The canary parses the NUL manifest, implements all 20 cells, creates real
hardlinks, preserves owner metadata, and emits the exact ledger. It is run in
normal Python and with assertions disabled.

The canary matters as a feasibility gate: it proves the task contract is
solvable with the declared Bash-native tool set. It is not a synthesized
candidate API, production sandbox, or score.

### 8. Hash-only publication and migration artifacts

The report publisher performs no-follow parent traversal, bounded stable
reads, exclusive temporary creation, complete writes and fsync, and an atomic
hardlink no-replace publish. An existing report is accepted only when its
bytes are exactly identical.

Coverage v2 and its migration record similarly bind:

- the exact v1 coverage digest, byte digest, byte count, and predecessor
  commit;
- the ninth registry and cumulative-suite digests;
- the new hardlink task-set and 20-signature discrimination digests;
- the fact that exactly one family changed.

Immutable publication matters because a report path that can be silently
replaced is not a useful experiment identity.

The accompanying JSON Schemas validate interchange shape and fixed principal
identities. They are not substitutes for lock admission; the exact Python
loaders require a reachable, mode-0644, link-count-one regular file whose
canonical bytes equal a fresh central reconstruction.

### 9. Mutation and optimized-mode tests

Tests reject split inodes, extra external links, wrong link groups, mutated
ledger bytes, changed inputs, symlink substitutions, stale scans, catalog
collisions, authority escalation, noncanonical JSON, duplicate keys, and
recursive-builder regressions. Core suites are repeated under `python -O` so
security or correctness cannot depend on `assert`.

Mutation tests are important because a verifier is characterized as much by
the incorrect states it rejects as by the reference state it accepts.

## Frozen identities

- Ninth added registry:
  `ff886754b054445a90ad30197d004e4071dba72bf0af17931d05e461c7e90703`
- Ninth cumulative task suite:
  `d0647e24f29abd59f8c2d6b2ac2a404aee78b92c780f8be4f9b16d200885843b`
- Hardlink integrated task set:
  `0415daa5f9bccfcd75b621ef4ae71c9e79a5b7c19763ceb470e5ef21169706d1`
- Grid discrimination evidence:
  `1a0c0d23bb262c1d94250a92574c89af6c6333da08d58be715e1b5d1f4940435`
- Ninth cumulative fixture catalog:
  `56932666f2641b5947e1801378b233dd5f37f568e4f2b4c6aa171bad115b09d8`
- Canonical 56,392-byte ninth report:
  `8bb43dfa235261ab5e237b26a5384d767a02ad351a8b3311fc909ad860b70b6b`
- Coverage v2:
  `7406480a1dc06bc99d1e36fde1a328a490d6cc8d6b96ee38c924a902acbf9abd`
- v1-to-v2 migration:
  `eb2b577e8449438c734174f361dea5c2c1ced9a3a68be383413dc6e727b8526f`

## What remains unproven

The verifier assumes the trusted harness has established candidate
quiescence; a stable pair of scans is not a proof that no hidden process can
mutate the workspace later. The reviewed Bash canary uses host tools whose
local hashes are not a production trust anchor. The family is public
development data, so it cannot estimate sealed generalization. Most
importantly, no model has yet been trained or compared: this tranche improves
measurement readiness, not terminal-specialization performance by itself.
