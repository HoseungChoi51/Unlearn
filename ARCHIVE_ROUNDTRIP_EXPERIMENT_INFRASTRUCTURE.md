# Compressed archive round-trip experiment infrastructure

## What this tranche is for

`compressed-archive-roundtrip-verify` is the tenth executable-static
development family. It tests whether a model can synthesize a Bash program
that builds a normalized ustar archive, selects the requested compression
format, reconstructs the declared files, and publishes a policy-specific
verification record.

This is useful for terminal-specialization research because it combines
quoting, binary-safe manifest handling, byte ordering, archive metadata,
compression, checksums, and final filesystem state in one bounded task. A
plausible-looking command is not enough: the trusted verifier parses the
candidate artifact and checks its semantics.

This tranche is benchmark infrastructure, not a model result. Its tasks and
fixtures are public method-development data. They are unsealed, unscored, and
ineligible for model selection or research claims.

## The 4-by-5 task grid

The first axis selects the archive encoding:

- `gzip`
- `bzip2`
- `xz`
- `none` (an uncompressed ustar)

The second axis selects the required final evidence projection:

- `archive-digest`
- `member-digests`
- `roundtrip-bytes`
- `roundtrip-bytes-and-modes`
- `strict-all`

All 20 cells face the same strict archive and round-trip correctness check.
The evidence policy changes the exact report fields that must be present; it
does not weaken archive validation. This distinction is important. A final
state can prove that an archive, reconstructed tree, and relational report are
consistent, but it cannot prove which commands the candidate ran or what
temporary checks it performed.

The implementation preserves the previously declared Bash-native tool
boundary: `bzip2`, `gzip`, `mkdir`, `sha256sum`, `sort`, `tar`, and `xz`.

## Components and why each matters

### 1. Exact task contracts and semantic graphs

Each task fixes the prompt, compression format, evidence policy, allowed
tools, output paths, archive semantics, and observation limits. The semantic
graph records the intended dependency structure: parse the manifest, order
members, build normalized ustar bytes, encode them, reconstruct the tree, and
publish evidence.

This layer matters because changing a codec flag, report meaning, or path rule
after training would change the experiment. Hash-bound contracts make such
drift visible and keep all seeds on the same task definition.

### 2. Generator-backed hostile fixtures

Each of the 20 tasks is paired with the five public edge-case profiles, for
100 fixture bundles. The fixtures cover spaces and Unicode, leading dashes
and glob metacharacters, empty and duplicate contents, reversed manifest
order, symlink distractors, nested paths, and varied owner-readable modes.
The manifest is NUL-delimited so paths are not reinterpreted as shell words
or newline records.

Hostile fixtures matter because archive scripts often appear correct on
simple names while failing on quoting, sort order, symbolic links, empty
files, or permission metadata.

### 3. Independent semantic derivations

The trusted side derives expected member semantics through separately
structured primary and reference paths before accepting a fixture. One path
uses the established ustar semantic machinery; the other independently
parses and groups the manifest and source records. Agreement is required
before an oracle bundle is admitted.

The two paths do not justify a claim that every downstream line of code is
independent. Shared assembly is instead covered by mutation tests, direct
parser tests, real-workspace verification, and the reviewed Bash canary.
Stating that boundary avoids overstating oracle diversity.

### 4. Canonical representative versus semantic acceptance

The trusted oracle stores one deterministic representative for each compressed
archive. The verifier does not require candidate compressed bytes to equal
that representative. gzip headers and xz encoders can legitimately differ
across implementations while decompressing to the same valid ustar stream.

Instead, the verifier:

1. selects the decoder from the task contract;
2. accepts exactly one complete, bounded stream under the closed format
   header policy, including gzip zero mtime/no optional fields and xz CRC64;
3. parses the decompressed ustar without extracting it;
4. compares the member set, order, bytes, modes, and normalized metadata with
   the fixture;
5. derives report digests from the candidate artifact and parsed members.

This separation matters because byte equality would reject portable correct
solutions. It does not mean every outer-stream byte is free: the explicit
header/integrity rules remain semantic, while encoder-specific bytes outside
those rules may differ. Unconstrained decompression would accept unsafe or
semantically different outputs.

### 5. Bounded single-stream codec decoding

gzip, bzip2, and xz are decoded through format-specific bounded APIs. The
decoder rejects truncation, failed integrity checks, concatenated streams,
trailing garbage, and decompressed output above the fixed cap. xz decoding
also has a memory limit. The `none` format is still subject to the same tar
byte bound.

Compression limits matter even in a rootless sandbox: a small candidate file
can otherwise expand into excessive memory or verifier work. Requiring one
stream also makes the family contract deterministic instead of inheriting
different utilities' concatenation behavior.

### 6. Strict safe ustar parsing

Trusted verification parses archive bytes directly and never calls
`extractall`. It accepts only canonical relative UTF-8 names, byte-sorted
unique regular-file members, normalized ownership fields, exact content and
modes, valid checksums and padding, and a complete zero-block terminator.
Absolute paths, parent traversal, duplicate members, extension records,
links, devices, malformed numeric fields, unsupported types, and data after
the terminator fail closed.

This is the core safety and correctness boundary. A filesystem extraction
API can perform path traversal or normalize malformed archives before the
verifier sees them; parsing first keeps untrusted member names inert.

### 7. Relational evidence reports

Reports are checked against the candidate-produced bytes, not copied from the
oracle representative:

- archive digests bind the exact candidate artifact;
- member digests bind parsed archive contents in canonical path order;
- round-trip records bind source and reconstructed bytes;
- mode-aware records additionally bind permission bits;
- `strict-all` combines the complete evidence set.

The report schema is closed and ordered. Missing, duplicate, reordered, or
extra records are rejected, and a report valid for one policy must fail the
other four policies.

Relational checking matters because a canonical gzip digest, for example,
would incorrectly turn an implementation choice into task semantics. It also
prevents a candidate from submitting a valid archive next to a report about a
different archive.

### 8. Exact final-state and input-preservation verification

The workspace verifier admits only the expected archive, report, round-trip
files, and required ancestor directories. It checks regular-file kinds,
contents, permission modes, zero reconstructed-file mtimes, link count one,
output closure, and the preserved input snapshot including visible hardlink
topology. It brackets reads with trusted scans to detect changes during
verification.

This layer matters because correct archive bytes do not excuse extra output
paths, symlink substitutions, hardlink aliasing, incorrect reconstruction, or
mutated inputs.

### 9. Non-recursive predecessor evidence

The first eight tranches already have a hash-neutral linear evidence path. A
separate through-ninth layer admits the frozen ninth registry and catalog once
and performs one global collision pass across 360 tasks and 1,800 fixtures.
The tenth registry and catalog then append 20 tasks and 100 bundles without
recursively rebuilding historical publication objects.

This matters operationally as the suite grows, and scientifically because the
optimized builder must still prove every predecessor identity rather than
silently trusting a count.

### 10. Fixed reviewed Bash canary

A hand-authored Bash program must solve all 100 task/profile combinations
under a restricted `PATH` containing exactly the seven declared utilities.
The canary runs with a fixed locale, timezone, and umask and clears archive
utility environment options that could alter behavior.

The canary is a feasibility gate. It demonstrates that the task is solvable
inside its declared tool budget before the family is promoted. It is not a
model output, scored candidate interface, or production sandbox.

### 11. Mutation and discrimination tests

Tests alter codec headers, payloads and footers; truncate streams; append
garbage; concatenate valid streams; exceed expansion limits; corrupt tar
headers and metadata; introduce unsafe, duplicate, unsorted, missing, or
extra members; substitute links; mutate reports; and alter inputs or the
round-trip tree.

Cross-format tests require each artifact to pass only its selected decoder.
Cross-policy tests require each final evidence projection to pass only its
selected policy. The fixture-oracle discrimination digest commits one distinct
signature for every task cell. Core tests also run under `python -O` so
correctness does not depend on assertions.

Mutation tests matter because a verifier is defined at least as much by the
incorrect states it rejects as by the reference state it accepts.

### 12. Immutable publication and coverage migration

The tenth hash-only report publishes task, fixture, generator, verifier, and
cumulative identities without fixture bytes or oracle answers. Publication
uses bounded stable reads and atomic no-replace semantics.

Coverage v3 preserves the exact v2 artifact as its predecessor, promotes only
`compressed-archive-roundtrip-verify`, appends the tenth registry commitment,
and records the new task-set and discrimination digests. A separate migration
record proves that the other 24 family declarations are unchanged.

This matters because regenerated JSON is not sufficient evidence if a path
can be silently replaced or if a new coverage document has no cryptographic
link to the plan it superseded.

The frozen tenth identities are:

- task set:
  `450ba507f0672e3a47ca6d495a6553d07294c605f94b3c5f03aa111d42bf771a`;
- added registry:
  `0d07fd82de275ffd9dc274b97a6fa02fdd0620f83d5ee90a2bea0ad64f06f0ab`;
- cumulative suite:
  `629119116c53a0be2cc7cacb5461ae13de7d50f29b0a129707a840089ab48d2f`;
- cumulative catalog:
  `5a29ea69111028fe69322d892e061a723ab53fb857ce4077cca924e314a4f4d6`;
- fixture-discrimination evidence:
  `ae95eef5802c010e70e338d257f5d0f3d01a39fa5cf471f945a8b75f554faa21`;
- canonical 56,553-byte
  [tenth manifest](reports/executable-tenth-tranche/manifest.json):
  `02442d60bf7d7874016fc9d50857cd49f9d8e1342ece55a42d7c8afcd852f0fb`.

The current
[coverage v3](configs/executable-method-development-coverage-v3.json) has
semantic SHA-256
`b37f48c98e7216c78ddf74d0ce6f6d74cd095575f20f53de6bf30018b2180d79`;
its 23,943 canonical bytes have SHA-256
`de241ad1e4536fa595f99acf0ef05a3e423418876298c576abe87249c018bc0a`.
The
[v2-to-v3 migration](configs/executable-method-development-coverage-v2-to-v3-migration.json)
has semantic SHA-256
`8e36252576376d86ddb0a4f3b399dfdd66377b0ed026369bbf799edf104818a2`;
its 4,358 canonical bytes have SHA-256
`77820327bc105d367d8d737c110e53e8183ce786650ecb4c1699991412cb6683`.

## What the family does not prove

The verifier observes a bounded final state. It cannot prove tool use,
verification operation order, pipeline exit status, atomic creation history,
temporary path behavior, causal derivation of the reconstructed tree from the
archive, or permanent quiescence after the trusted harness stops observing.
It also cannot prove encoder choices beyond the outer-stream properties that
the semantic decoder explicitly checks. Those are explicit assurance limits,
not implied capabilities.

The public fixtures also cannot estimate sealed generalization. Most
importantly, no model comparison follows from this tranche alone. It improves
the experiment's measurement readiness; terminal-specialization claims still
require the locked training arms, fresh seeds, protected-capability checks,
sealed executable evaluations, and the statistical acceptance rules in
`PLAN.md`.
