# Implementation status

This file separates implemented and tested infrastructure from the research
campaign specified in [PLAN.md](PLAN.md). A checked infrastructure item is not
evidence that a model or research hypothesis has succeeded.

## Foundation milestone

- [x] Python package and command-line entry point with no mandatory runtime
  dependencies.
- [x] Deterministic static and bounded-terminal split generation at smoke and
  plan scale.
- [x] Immutable semantic records, normalized graph hashes, split-family
  isolation checks, fixture-descriptor edge-case coverage, canonical JSONL,
  and content-addressed manifests.
- [x] Full generated-artifact verification against external digest pins,
  declared hashes/counts, typed records, and deterministic regeneration.
- [x] Frozen raw/one-fence response extraction and evaluation-spec-driven,
  hash-only, non-executing host syntax gates.
- [x] Hardened non-root Docker/Podman command construction, intended for a
  separately verified rootless daemon, with no network, bind mounts, added
  capabilities, or writable root filesystem.
- [x] Versioned JSON Schema and semantic validation for completed experiment
  records and hardware-result manifests. Completed records are bound to a
  prospective run-spec digest, effective operator/training protocol, export
  identity, token counts, and FLOP limits. Hardware results can be exactly
  bound to that completed export rather than accepted as standalone claims.
- [x] Prospective dense sub-1B run specifications with explicit input
  provenance, lifecycle-routed split roles, operator decisions, token/compute
  budgets, and export intent.
- [x] Immutable PLAN-derived campaign profiles for screening, confirmation,
  and runner-up phases, including exact token mixtures, optimizer/training
  protocol and freezing-mode learning-rate grids, fresh-seed metadata, an
  external policy digest, and validation at
  both planning and completed-record boundaries.
- [x] Content-addressed campaign registry that jointly validates the complete
  run-spec/completed-record roster, exact 2/5/5 replicate coverage, paired
  seed and data commitments, stable per-arm run protocols, cohort-wide
  verified teacher-corpus identity, within-cohort uniqueness and cross-phase
  field-wise freshness for every training-affecting seed, dense sub-1B exports,
  declared promotion links, prospective per-run contrast roles that derive
  exactly one all-reference and one all-comparison arm for each confirmatory
  cohort, and one
  artifact-bound evaluation per run for every declared confirmatory suite.
  Confirmatory cohorts are exactly two-arm fixed-size or compression
  contrasts with prospectively ordered reference/comparison roles; the
  comparison arm must directly name the reference in `source_arm_id`.
  This direct-baseline rule is operator-neutral, so compression controls may
  themselves use pruning or quantization. The registry verifies declared-link integrity; it does not prove
  metric-based promotion or pilot-backbone eligibility because the frozen
  policy does not encode those decisions.
  This closes registry-only role reversal; external publication or timestamp
  trust for prospective run-spec hashes is still required because validators
  cannot distinguish a wholly rewritten run-spec/completed-record history.
- [x] Explicit training dtype, optimizer-state dtype, microbatch,
  accumulation, data-parallel, packing, loss, and freezing contracts, plus
  selection-strategy semantics that distinguish zero-compute controls from
  task-aware selection.
- [x] Prospective scored-evaluation specifications that pin dense artifact and
  external inspection-report identity, benchmark identities, sealed-split
  routing, deterministic decode/parser, sandbox limits, tool and fixture
  rules, outcome taxonomy, seeds, canonical per-task commitments, an external
  analysis-plan/code commitment, deterministic bootstrap/randomization
  policies, simultaneous-inference policy, and hash-only output policy.
  Confirmatory plans copy the registry's exact ordered arm-role object rather
  than committing only an unordered arm set.
  Confirmatory static contracts require exactly 1,000 sealed-ID or 500
  sealed-OOD tasks and freeze PLAN-derived margins and thresholds. This is a
  validation contract only; it does not inspect tensors or reports, open
  benchmark assets, execute candidates, or prove a multi-artifact seed set.
  Its artifact and training seed can be exactly bound to one completed dense
  export by canonical record and artifact hashes.
- [x] Hash-only per-task result records with stage-order, fixture, resource,
  action-trace, and terminal-status invariants for static and interactive
  evaluation, cryptographically and semantically bound back to the prospective
  task/fixture inventory, ordered fixture sequence, and resource limits.
  Per-invocation measurements must reproduce aggregate maxima exactly. Later
  attempts are accepted only through an execution-only validator that verifies
  the complete canonical prior-result hash and status chain; collection
  validation requires exact task coverage and complete retries, while scored
  selection returns one result per task with an exhausted-infrastructure
  failure fallback. Exclusions remain fail-closed until typed evidence exists.
- [x] Dependency-free confirmatory statistics for complete paired binary
  arm-by-training-seed-by-semantic-task cubes: macro pass@1, deterministic
  crossed seed/task percentile bootstrap, exact or deterministic-Monte-Carlo
  paired sign-flip tests, Holm step-down adjustment, and interval-based
  non-inferiority decisions.
- [x] Schema-locked in-memory confirmatory analysis adapter that validates the
  supplied evaluation spec, binds its exact arm/seed/task cube and prospective
  analysis policy, derives comparison-minus-reference direction from the
  frozen ordered roles, applies percentage-point conversion, and finalizes exactly
  one fixed-size plus one compression contrast. Its outputs explicitly state
  that supplied code bytes are provenance rather than runtime attestation.
- [x] Artifact-bound outcome construction that reopens a validated campaign
  registry and its complete scored task-result collections, reselects the
  scored attempt for every declared arm/seed/task cell, derives the paired
  binary cube without accepting caller-supplied rows, binds the cube and
  source-collection hashes, and immediately executes the frozen contrast.
- [x] Fail-closed claim-policy evaluator for fixed-size and compression lanes.
  It joins typed statistical, export-layout, matched-token, matched-FLOP,
  non-inferiority, hardware, replication, and teacher-free projections and
  reports every policy decision, but deliberately emits
  `claim_authorized: false` until each projection is reopened and rederived
  from its named source artifact by the seven enumerated validator chains.
- [x] Unit and CLI integration tests that run without a GPU or container
  engine.
- [x] Executable-static first tranche with five public-development families:
  active-label JSONL, copy-map, CSV-totals, checksum-mode, and path-suffix
  inventory. Exactly 100 method-development semantic specifications are each
  instantiated under five concrete edge-case profiles, yielding 500
  content-bound bundles with deterministic `FixtureDefinition` inputs and
  trusted oracles. Descriptor-relative no-follow materialization, semantic
  verifier/evidence records, independent reference constructions for every
  family, and all-500 trusted-oracle materialization and mutation-rejection
  tests are implemented. The tranche never executes candidate code and is
  public, unsealed, unscored development data.
- [x] Additive executable-static second tranche with five more
  public-development families: byte transforms, mode normalization, strict
  JSONL inner joins, raw POSIX-ustar extraction, and synthetic process
  snapshots. Another 100 semantic specifications and 500 deterministic
  bundles bring the cumulative public method-development inventory to 200
  tasks and 1,000 fixtures. All added bundles pass independent-oracle,
  descriptor-relative materialization, no-follow, mutation, normal-mode, and
  optimized-mode tests. The hash-only additive manifest preserves the frozen
  first-tranche identities and keeps execution, model-selection, and claim
  authority false.
- [x] Additive third-tranche `compound-path-query` public-development family
  with 20 typed task contracts and five deterministic profiles per task (100
  fixtures). Its fixed basename-pattern and parenthesized kind/mode/depth
  predicates have two structurally independent production oracles that must
  agree, plus mutation, exact-type, materialization, pinned-workspace,
  no-follow, and normal/optimized-mode tests, including 20 genuine zero-byte
  results and 15 workspace-state mutations. Its workspace verifier binds the
  task/profile/bundle to an already-open directory, requires the exact input
  baseline and complete output policy, and repeats bounded scans after reads.
  Those scans cannot establish global quiescence without a trusted supervisor.
  The additive third registry and catalog admit its exact family-local task and
  bundle types without changing either earlier tranche identity. It remains
  outside `DevelopmentInvocation` and has not completed independent human
  production review. Because the fixture type cannot represent explicit
  directory modes, its `partial-permissions` profile covers mode-denied leaves,
  not directory permission errors.
- [x] Additive third-tranche `regex-log-group-aggregation` family with another
  20 task contracts and 100 fixtures. It covers recursive no-follow `.log`
  selection, byte-oriented ERE filters, strict UTF-8/TSV/integer parsing, five
  malformed-row policies, count/sum grouping, raw-byte ordering, symlinks,
  unterminated and malformed bytes, and mode-bit-readable leaves. Two
  independently structured production oracles must agree. Its fail-closed
  workspace verifier authenticates the task/profile/bundle and pinned handle,
  requires the exact input baseline, enforces the complete output tree and
  mode/link/size policy, uses bounded descriptor-relative egress, and closes
  changes observed during verification with final scans. A trusted supervisor
  must first establish descendant quiescence; sequential scans alone cannot
  close a concurrent-writer race. Directory-mode and effective-access failures
  remain explicitly uncovered. The third additive registry/catalog admits its
  exact family-local types but does not add V1 invocation support. Together the
  third-tranche families add 40 tasks/200 fixtures, bringing the cumulative
  public-development identity to 240 tasks/1,200 fixtures while all execution,
  model-selection, and claim-authority flags remain false.
- [x] Backward-linked content-addressed method-development coverage lock for
  exactly 25
  families, 20 tasks per family, and 500 tasks total. The canonical 4-by-5
  parameter grids bind each family's lifecycle state, Bash-native or
  Python-permitted solution track, allowed tools, filesystem schema, output
  contract, and capability tags. V1 is preserved as historical planning
  evidence. V2 reconciles 18 integrated families/360 tasks to all nine live
  cumulative registry identities and reserves 7 concrete families/140 tasks
  without pretending that planned entries have fixtures or verifiers. The
  v1-to-v2 migration record proves that only the hardlink family changed after its v1
  grid was found to contain redundant, nondeterministic, and nonorthogonal
  cells. V3 preserves exact v2 bytes, promotes only
  `compressed-archive-roundtrip-verify`, reconciles 19 integrated
  families/380 tasks to ten live cumulative registry identities, and reserves
  6 concrete families/120 tasks. Its v2-to-v3 migration record proves the
  other 24 family values are unchanged. All configs are public, unsealed,
  unscored, nonauthorizing, and record no independent human-review
  attestation.
- [x] Additive fourth-tranche `reproducible-ustar-pack` family with 20 task
  contracts and five deterministic profiles per task (100 fixtures). It
  crosses four mode-readable selectors with five archive-mode policies,
  writes only normalized POSIX-ustar regular members in UTF-8 byte order, and
  requires exact source preservation and output-tree state. Two independently
  structured semantic constructions agree; a strict parser, property
  verifier, and targeted checked-in mutation tests cover its archive contract.
  A separate implementation-session audit exercised randomized differential
  cases and GNU-tar interoperability, but that result is not yet a checked-in
  reproducible audit artifact. It uses exact
  family-local task/bundle types, preserves every earlier tranche identity,
  and remains outside V1 invocation. Final-state verification cannot attest
  transient `chmod`, symlink-follow, or tool history, and explicit directory
  permission and live effective-access failures remain uncovered.
- [x] Additive fifth-tranche `pipefail-atomic-report` family with 20 task
  contracts and five deterministic profiles per task (100 fixtures). It
  crosses four complete-stream logical pipeline shapes with five
  failure-publication policies, including required output absence, status
  publication, byte-exact rollback, and first/last failure selection. Two
  separately structured semantic constructions agree on the full ordered
  status vector, shape-specific aggregation, selected failure, and exact
  final report state. Checked-in catalog materialization, mutation,
  randomized-stream, exact-type, no-follow, and normal/optimized-mode tests
  cover that final-state contract without executing a candidate. Exact local
  task/bundle types preserve every predecessor identity and remain outside V1
  invocation. The contract prescribes sibling-file atomic rename and complete
  status capture, but final-state inspection cannot observe atomic-rename
  history, Bash `PIPESTATUS`, pipeline topology, or tool history. Trusted
  quiescence is required; global quiescence, explicit directory-permission
  errors, and live effective-access failures remain unobserved.
- [x] Additive sixth-tranche `bounded-retry-state-machine` family with 20 task
  contracts and five deterministic profiles per task (100 fixtures). It
  crosses four transition models with five behaviorally distinct retry
  policies: one-, two-, four-, and six-attempt state-visit budgets, with
  transient/ordinary retry eligibility separated while terminal failures
  always stop retrying, and every budget resets per state/visit. Two
  separately structured parsers and simulators agree on exact attempt and
  terminal reports for branch selection, bounded cycles, compensation, empty
  ledgers, missing events, and causes.
  Checked-in materialization, mutation, parser, type, hash-seed, policy-
  discrimination, and normal/optimized-mode tests do not execute a candidate.
  Exact local task/bundle types preserve all predecessor identities and remain
  outside V1 invocation. Final-state verification cannot attest actual retry,
  wait, transition, compensation, tool-use, atomic-publication, transient-input,
  global-quiescence, or candidate-exit history; directory-permission and live
  effective-access failures remain uncovered.
- [x] Additive seventh-tranche `case-routed-batch-transform` family with 20
  task contracts and five deterministic profiles per task (100 fixtures). It
  crosses four mutually exclusive routing signals with five unmatched-record
  fallback policies and binds exact status, error, route-partitioned payload,
  input-preservation, and final-tree semantics. Two separately structured
  parsing, routing, transform, and serialization paths must agree. Exact-type,
  deterministic-regeneration, materialization, no-follow, mutation, and full-
  catalog tests exercise the family without candidate execution. One fixed,
  source-reviewed Bash program also passes all 100 public fixtures under a
  restricted tool `PATH`, with an additional binary-stream case. That canary
  is not a caller-selected candidate API, production sandbox, scored result,
  model-selection result, or research claim. Final-state verification cannot
  attest route, transform, read-scope, tool, atomic-publication, exit-status,
  transient-input, or global-quiescence history; directory-permission and live
  effective-access failures remain uncovered. Exact local types preserve all
  predecessor identities, and the family remains public, unsealed, unscored,
  nonauthorizing, outside V1 invocation, and without independent human review.
- [x] Additive eighth-tranche `collision-safe-batch-rename` family with 20
  task contracts and five deterministic profiles per task (100 fixtures). It
  crosses four flat-destination rename rules with reject-all, skip, stable-
  first, stable-last, and exact-byte-coalescing policies. Two independently
  structured parsers, destination builders, grouping/planning paths, and
  ledger serializers must agree on an immutable source-action plan and exact
  outputs. The mutation-aware verifier requires removed sources to be absent,
  retained leaves to equal their authenticated baseline, original input
  directories to preserve kind/mode/link topology, and every published file
  to preserve its representative's bytes, size, mode, and modification time.
  Exact-type, deterministic-regeneration, all-100-bundle materialization,
  source/output mutation, normal/optimized-mode, and no-process-construction
  tests cover the family. A fixed source-reviewed Bash canary realizes all 20
  grid cells on the binary profile under a restricted tool `PATH`, with a
  separate all-byte and NUL-boundary equality probe. The canary is not a
  caller-selected candidate API, production sandbox, score, model-selection
  result, or research claim. Final-state verification cannot attest actual
  rename or inode identity, collision-decision, read-scope, tool-use, staging,
  atomic-publication, crash-rollback, transient-input, global-quiescence, or
  candidate-exit history; directory-permission and live effective-access
  failures remain uncovered. Exact local types preserve all predecessor
  identities, and the family remains public, unsealed, unscored,
  nonauthorizing, outside first-tranche-only V1 invocation, and without
  independent human review.
- [x] Additive ninth-tranche `hardlink-deduplicated-mirror` family with 20
  task contracts and five deterministic profiles per task (100 fixtures). It
  crosses four fixture-distinguishable equivalence keys with five
  deterministic metadata-owner policies. The fixtures contain a four-way
  partition probe, five-way owner probe, pre-existing input hardlinks, exact
  committed mtimes, symlink distractors, binary and empty data, hostile
  pathnames, and mode variation. Dictionary-partition and sorted-stream
  semantic engines must agree. The workspace verifier checks exact bytes,
  modes, mtimes, input preservation, output link counts, and portable visible
  hardlink-group digests; split-inode, external-link, ledger, input-alias,
  type, and hash mutants are rejected. A fixed source-reviewed Bash canary
  solves all 100 public bundles using exactly `cp`, `find`, `ln`, `mkdir`,
  `sha256sum`, `sort`, and `stat`. Linear predecessor evidence reconstructs
  each earlier task tranche and fixture catalog once while preserving all
  frozen identities. The family remains public, unsealed, unscored,
  nonauthorizing, outside first-tranche-only V1 invocation, and without
  independent human review. Its final-state verifier assumes trusted
  quiescence and cannot attest creation, tool, transient-path, or exit-status
  history.
- [x] Additive tenth-tranche `compressed-archive-roundtrip-verify` family
  with 20 task contracts and five deterministic profiles per task (100
  fixtures). Four outer formats cross five closed evidence-report
  projections, while all cells retain identical normalized-ustar,
  reconstructed-tree, output-closure, and input-preservation semantics. The
  trusted verifier accepts exactly one bounded selected-format stream, parses
  decompressed ustar bytes without extraction, and derives report evidence
  from the actual candidate artifact. Wrong format, truncation,
  concatenation, trailing data, expansion-limit, unsafe/member/tar/report,
  input, and final-tree mutants are rejected in normal and optimized modes.
  A fixed source-reviewed Bash canary solves all 100 public fixtures with
  exactly `bzip2`, `gzip`, `mkdir`, `sha256sum`, `sort`, `tar`, and `xz`.
  Through-ninth predecessor evidence reconstructs every predecessor identity
  once before the tenth registry/catalog append. The family remains public,
  unsealed, unscored, nonauthorizing, outside first-tranche-only V1
  invocation, and without independent human review. Its final-state verifier
  assumes trusted quiescence and cannot attest verification order, tool use,
  transient state, causal reconstruction, global quiescence, or exit status.
- [x] Dependency-free, read-only local Safetensors artifact inspection with
  strict JSON and shard-layout validation, no-follow stable reads, resource
  ceilings, domain-separated bundle/weight/tokenizer identities, stored tensor
  element/byte/component accounting, and conservative dense/MoE evidence.
- [x] Exact static dense-checkpoint qualification for the supported Qwen2,
  Qwen3, and Llama contracts. It reconstructs every tensor name and shape,
  counts unique physical parameters, checks single floating dtype against
  payload bytes, derives tensor roles and operator bounds, and remains
  permanently nonauthorizing. A prospective run-spec binder rebinds the exact
  generic report and tokenizer, enforces GQA groups and exact factorization
  tuples, reconciles architecture-representable layer/uniform-FFN-width/
  all-layer-Qwen3-GQA-head/vocabulary
  pruning, and derives a selected-plus-unselected quantization payload lower
  bound. Unsupported physical shapes and hybrid exports fail closed.
- [x] Optional, local-only causal-LM runtime qualification for statically
  accepted flat Safetensors bundles. It rejects custom code, performs one
  bounded non-generative finite-logit forward pass, rechecks artifact
  stability, and reports exact physical and trainable storage spans while
  counting tied/shared storage once. Saved reports now have a bounded passive
  validator that rederives loader, shape, storage, dtype, device, and
  qualification invariants rather than checking only the outer digest. This
  is runtime compatibility evidence, not independent runtime attestation,
  architecture completeness, or model-quality evidence.
- [x] Non-claiming GPU engineering pilot for all three preregistered dense
  backbones on the local RTX 5090: static inspection, CUDA runtime
  qualification, and seeded-input synthetic BF16 optimizer microfits with
  peak-memory and throughput records. CUDA optimization is not claimed to be
  bitwise deterministic. The maintainer-only microfit script is intentionally
  repository-local rather than an installed wheel command. The
  content-addressed report bundle explicitly forbids model selection and
  contains no terminal, capability, or benchmark measurement.
- [x] Dependency-free Docker/Podman metadata preflight with a fixed read-only
  command allowlist, bounded capture, executable and local image identity,
  engine-native rootless evidence, current-cgroup controller evidence, and a
  fail-closed, content-addressed decision that never authorizes untrusted code.
- [x] Content-addressed logical training-corpus preparation with exact raw CSV
  and dataset-card pins, deterministic source replay, exact-pair deduplication,
  two-partition record and sequence hashes, explicit unresolved license
  provenance, no-import test split, stable no-follow reads, and atomic
  no-replace publication. Structural verification is kept separate from
  authentication; training callers require an external pin or raw-source
  replay. The current target remains upstream-unverified and non-claiming.
- [x] Tokenizer-aware exact schedule construction for whole records with
  response-plus-EOS labels, deterministic partition cycling/interleaving,
  exact-tail subset selection, fixed-length packing, tokenizer/model-row
  identity, binary stream hashes, independent full reconstruction, and exact
  target/support/visible/supervised/padding ledgers. The checked-in engineering
  record binds a 2M-token Qwen3 schedule but explicitly does not attest a
  trainer execution or target-policy admission.
- [x] Conservative, no-execution lexical source audit with normalized-prompt
  ambiguity rejection, positive executable allowlisting, dynamic/path/wrapper
  and embedded utility-escape detection, privacy-safe rejection ledgers,
  bounded histograms, Python/Unicode and transformation-code provenance,
  descriptor-pinned validation, atomic no-replace publication, and complete
  raw-source reconstruction for authenticated use. The real NL2SH-ALFA import
  yields 4,748 static candidates and 35,785 rejections; every candidate remains
  explicitly unparsed, unexecuted, non-admitted, and non-claiming.
- [x] Catalog-bound public-development invocation framing. One exhaustive
  validation admits only the frozen first-tranche registry/suite/catalog
  identities for repeated use; each invocation remains bound to and
  revalidates its selected task, profile, and fixture bundle. Canonical request
  frames bind the original response, the frozen-parser Bash extraction, and
  answer-free fixture inputs/output policy without oracle answer bytes. The
  reverse protocol admits only an invocation-bound blocked result.
- [x] One fixed, reviewed, nonexecuting Bash integration case. It exhaustively
  admits the frozen first catalog, pins an exact path-suffix-inventory task and
  `spaces-unicode` fixture, binds one fenced response through the frozen parser
  and invocation protocol, and authenticates the case before existing
  descriptor-relative materialization. The source uses Bash builtins plus only
  `find`, `mkdir`, and `sort`. Its audit projection excludes fixture, oracle,
  response, and program bytes, and all execution, scoring, selection, and
  claim fields remain false.
- [x] Fixed reviewed-candidate binary transport protocol with exact 384-byte
  request and 512-byte result layouts. The request binds invocation, program,
  fixture definition, workspace baseline, runtime snapshot, allowed tools,
  policy, nonce, and resource ceilings; the protocol version separately fixes
  descriptor roles. The result repeats
  every identity and binds classified process outcome, cap-plus-one stream
  observations and digests, separate cumulative `wait4` user/system totals,
  the enforced cumulative maximum including live namespace-tree CPU, wall
  time, descendants reaped, and the post-run workspace snapshot. Strict parsing, cross-record
  binding, malformed-frame, mutation, and normal/optimized-mode tests are
  complete. This is transport only: it opens no descriptor, constructs no
  namespace, executes no program, verifies no workspace, and permanently
  denies candidate, scoring, model-selection, and claim authority.
- [x] Candidate-input-free execution of the one fixed reviewed Bash case. The
  controller reconstructs the frozen invocation and descriptor-pinned
  workspace, materializes a host-pinned Bash/find/sort/mkdir ELF closure,
  rebuilds and seals the checked-in static native supervisor, and transfers
  the exact program, fixture identity, writable snapshot sink, workspace, and
  runtime payloads through systemd `OpenFile=` descriptors into a fresh
  rootless Bubblewrap namespace. The launcher receives a 16 MiB per-file
  ceiling so Bubblewrap can materialize the largest pinned runtime payload;
  native PID1 lowers the Bash child to a 1 MiB `RLIMIT_FSIZE` before exec.
  Native PID1 applies the fixed child policy,
  bounds and hashes both streams, enforces cumulative CPU and wall limits,
  kills and reaps descendants, and serializes only the workspace root and
  paths outside top-level `input`. After the transient cgroup is inactive and
  empty, the controller seals and binds that snapshot, independently
  revalidates the omitted descriptor-pinned input tree, compares the
  output-side projection, and runs the existing property verifier. The public
  execution entry point accepts only an optional nonce and no caller-selected
  program, command, fixture, runtime, or verifier. It executes one reviewed
  program only; arbitrary candidates, runtime-data and
  `dlopen` closure, external trust, a general Bash seccomp/exact-tool policy,
  scoring, model selection, and claims remain false.
  Its public snapshot record omits raw payload bytes but retains paths, modes,
  sizes, and payload digests. It is not answer-confidential or eligible for
  reuse across a sealed boundary or as benchmark feedback.
- [x] Public-development systemd-user/bubblewrap namespace and cgroup canary
  inspection plus a content-safe candidate launch-plan builder that accepts
  only an exact validated `DevelopmentInvocation`. The execution entry point
  always raises before launch and records the missing trusted PID1 supervisor,
  child seccomp, CPU-time watcher, bounded capture, quiescence, exact-tool, and
  pinned-host-utility gates, including unpinned host `/usr`. This is
  development evidence only, never scored sandbox evidence.
- [x] Content-addressed development runtime source-closure manifests for
  explicitly named ELF executables. Descriptor-relative no-follow inspection
  records `PT_INTERP`/`DT_NEEDED`, ordered library searches and negative
  lookups, and declared usr-merge aliases beneath pinned roots, with aggregate
  payload/entry bounds and strict replay/race checks. This source manifest does
  not establish the wider runtime-data/`dlopen` closure or authorize a launch.
- [x] Nonlaunching development runtime materialization from a manifest matching
  a separately trusted expected digest. It copies into a new
  descriptor-relative no-follow destination, normalizes regular-file modes to
  source read/execute bits with write and privilege bits removed, seals
  directories to `0555`, replays source identity before and after copying, and
  records a bounded double-scanned projection. Structural evidence validation
  is separate from a live, point-in-time source/destination rebinding check.
  Evidence hard-codes same-UID mutation resistance, fd-bound launch handoff,
  launch eligibility, candidate authorization, scored eligibility, and claim
  eligibility to false.
- [x] Immutable development-runtime regular-payload snapshots and a fixed-
  protocol subprocess descriptor-handoff canary. The snapshot rebinds the trusted
  manifest and materialization evidence, pins and scans the complete runtime
  projection before and after capture, copies each regular into a CLOEXEC
  memfd, and verifies the exact write/grow/shrink/further-seal mask. Consumers
  receive independently reopened read-only descriptors so offsets are not
  shared. Descriptor-free records bind the manifest, materialization evidence,
  projection, slot inventory, counts, and payload hashes. The canary proves
  both CLOEXEC absence and an exact, exclusive `pass_fds` handoff to one frozen
  content-hashed helper through the already-open, content-hashed interpreter
  FD. The interpreter has no external trust anchor, so harmless-executable
  evidence remains false. This descriptor-only canary leaves memfd-mode
  immutability, directory/symlink namespace reconstruction,
  runtime-data/`dlopen` closure, systemd, Bubblewrap, launch, candidate,
  scored, and claim flags false.
- [x] Candidate-input-free, fixed-protocol runtime namespace canary for the
  snapshot-bound `/usr/bin/busybox` probe request only. It accepts exactly the
  three directories `/`, `/usr`, and `/usr/bin`, one regular probe payload,
  and no symlinks or additional runtime files. The constructed command asks
  user-systemd `OpenFile=` to transfer the sealed descriptor and asks
  Bubblewrap `--ro-bind-data` to project it without reopening a mutable runtime
  source path; the final mount operation remounts the root read-only. The
  built-in runner has bounded wall time, per-stream capture, systemd
  memory/PID/NOFILE/CPU-quota properties, and fixed cleanup, and it accepts
  only the hash-bound probe input and exact bounded JSON response frame.
  Locally hashed systemd/Bubblewrap/systemctl and probe executables are not an
  external trust anchor: payload/root mutation, descriptor closure,
  workspace/network/host-path isolation, the two handoffs, projected
  payload/mode, and probe execution therefore remain untrusted self-reports
  and their verification flags stay false. This narrow canary also does not
  establish harmlessness, Bash runtime-data/`dlopen` closure, a trusted
  supervisor/PID1, child seccomp, a cumulative CPU watcher, candidate output
  classification, descendant quiescence, exact-tool policy, or
  synthesized-candidate/scored/claim authority. The sole snapshot payload is
  still executable program bytes and is not semantically proven to be BusyBox.
- [x] Candidate-input-free native supervisor lifecycle canary with an exact
  64-byte request and 256-byte authenticated result protocol. The runner
  rebuilds the pinned descriptor for the checked-in C source with one fixed
  static-PIE compiler contract,
  requires a caller-pinned source digest and byte-for-byte agreement with the
  supplied binary, seals that binary behind an already-open descriptor, and
  projects it as PID1 in a fresh Bubblewrap user/PID namespace inside a
  user-systemd cgroup envelope. Nine closed scenarios exercise normal exit, a
  real double-fork plus `setsid`, an unreaped intermediate zombie, wall-time
  termination, independent stdout/stderr cap-plus-one overflow, CPU fan-out,
  a forbidden syscall, and result-frame spoof bytes. The fixed supervisor
  installs child-only `no_new_privs`, non-dumpability, and raw-BPF seccomp;
  captures streams itself; kills the namespace process set; reaps every child
  with cumulative `wait4` accounting; requires itself to be the sole remaining
  PID; and emits one request-bound digest-protected result. On normal and
  abnormal controller paths, pinned `systemctl` kill/stop operations are
  followed by an exact inactive/dead/empty-control-group query and synchronous
  wrapper reap. Evidence binds the
  suite nonce, every request/result pair, compiler/build identity, source and
  binary, launch contract, and all nine results. The default live suite passes
  on the development host; its protocol and controller unit suites also pass
  in normal and optimized Python modes. This is still a fixed-child lifecycle
  canary: local hashes are not an external
  trust anchor, the seccomp filter is not a synthesized-Bash policy, CPU time
  is observed but not cumulatively limited, and no candidate, workspace,
  runtime closure, tool policy, score, model selection, or claim is admitted.
  All corresponding authority fields remain false.
- [x] Real-text dense full-model SFT engineering canary with authenticated
  source/schedule reconstruction, response-plus-EOS loss, actual-supervised-
  token accumulation including the final partial update, optimizer-update LR
  scheduling, BF16 parameters/forward with FP32 AdamW moments, hash-chained
  update/FLOP accounting, local-only Safetensors loading, stable source-model
  checks, separate flat model export, streaming no-follow file inventory,
  logical-tensor hashing, static exported-model reinspection, and atomic
  no-replace publication. The 2M-token Qwen3 run completed and is versioned as
  a non-claiming engineering report; its raw target schedule is not admitted
  research data.
- [x] Content-addressed capability-support screening contract for the exact 13
  PLAN candidate families. It binds the current PLAN and roster hashes, dense
  sub-1B model and suite identities, 400 semantic items per family, full prompt
  and prefix-variant coverage, rational objective chance floors, paired
  before/after outcomes, and candidate-down/target-up probe direction. It can
  produce only a follow-up-audit roster and never infer irrelevance,
  dispensability, sacrifice authority, training authority, or a claim.

The executable-static first tranche is bound by the checked-in hash-only
[`reports/executable-first-tranche/manifest.json`](reports/executable-first-tranche/manifest.json):
registry SHA-256
`ada6043b345e48f69ad602581030aab1bafcb3ff9dc453f9d02342faaf6a7f9a`,
suite SHA-256
`eb64bb4cdb60ab8e0e228f688cf54810fae2ef56768e8b34ac039bdc1aec42ae`,
and catalog SHA-256
`1fc71f89830739a53b69d771b7d0bd6a79a4d78ff698b1c1c2258211e7776c99`.
The manifest keeps `candidate_execution_authorized`,
`model_selection_eligible`, and `claim_authorized` hard false. This tranche is
the immutable base for the additive
[`reports/executable-second-tranche/manifest.json`](reports/executable-second-tranche/manifest.json).
The addition binds another 100 tasks and 500 bundles with added-registry
SHA-256
`27e4721036c4870fec463e880cb3a36fcd72ebe530368cb45179f600ee694ab4`,
cumulative-suite SHA-256
`0020c1e5c7907d979d7fa97dead79f199fff59d97184c33fae81bc98df3ef8fb`,
and additive-catalog SHA-256
`e2ad6a3124491bc25410d40278400aeac9cd8791a9f08a530c823d5f14c09e18`.
The additive third tranche is bound by
[`reports/executable-third-tranche/manifest.json`](reports/executable-third-tranche/manifest.json).
It admits 40 tasks and 200 bundles from `compound-path-query` and
`regex-log-group-aggregation` through their exact family-local types, leaving
both earlier identities unchanged. Its added-registry SHA-256 is
`66a9ef43a6387f5f94f511aec3357f0e625427d161a0c6da0d9590a837761237`,
its cumulative-suite SHA-256 is
`3a578668805bbdfdfaf3400483640bb29504591604ed1c9c28cf8f9bb0362fb3`,
and its additive-catalog SHA-256 is
`01554367fd68c36b2f509b8b50b270b0aa7d5e6de3fa55db15a14cf4ec68c26b`.
The canonical report byte SHA-256 is
`58e7e299142bd2c9681f9940f8277489115fa76350ffa53fb984bed81ceac862`.
The additive fourth tranche is bound by
[reports/executable-fourth-tranche/manifest.json](reports/executable-fourth-tranche/manifest.json).
It admits 20 tasks and 100 bundles from `reproducible-ustar-pack`, again through
exact local types. Its added-registry SHA-256 is
`3dc5512139361a275afaf0b57b94528961615f9b4eee22ee6c333cc7d8bf4ea5`,
its cumulative-suite SHA-256 is
`668ab9c942888d568c80aaa27bee340ad8a10faf3493a6983bf068d79b134651`,
its additive-catalog SHA-256 is
`54ff2e17645edfc7887fc39b437340ffe8d736b83001d0265612271c2a3b1d46`,
and its canonical 56,273-byte report SHA-256 is
`a79ba062de86574e95ff60ff4fa8bc48b223c934b70d65ed832da5631359eebb`.
The family's task-set SHA-256 is
`be044d13053e62e0a9f609e1654048de4c7b422e9bc93c659f0d265ddfd4e283`.

The additive fifth tranche is bound by
[reports/executable-fifth-tranche/manifest.json](reports/executable-fifth-tranche/manifest.json).
It admits 20 tasks and 100 bundles from `pipefail-atomic-report` through exact
local types. Its family task-set SHA-256 is
`fc974695fe967094bcba6c6f8ff8c267c86f64215de78c43a8e693bed1252562`,
its added-registry SHA-256 is
`d562d462814b7fc6413e0e085d16f66def28157c1a6361adf28cd3d42eb5f88c`,
its cumulative-suite SHA-256 is
`27ea8064a72453a4e7a4bc52b125a924139088cd1c20d417a867aa9ddda96e00`,
its additive-catalog SHA-256 is
`cb24e42fc27500fa5076224dfc195a6fe2a4b08752724f09ff944961aa7221db`,
and its canonical 56,246-byte report SHA-256 is
`80959058c764da72437bfa1bd01a2eb1c747a221ec1c06f59278c02b80e0ef48`.

The additive sixth tranche is bound by
[reports/executable-sixth-tranche/manifest.json](reports/executable-sixth-tranche/manifest.json).
It admits 20 tasks and 100 bundles from `bounded-retry-state-machine` through
exact local types. Its family task-set SHA-256 is
`112e9d079a1b21b2d371e61d48af2401649b23aeff11a45e4d2dcbe847e1541c`,
its added-registry SHA-256 is
`14280b3cbc8a96c919a57a325b5795c381cba86b2a31934f7069821b7ff4e3c4`,
its cumulative-suite SHA-256 is
`db6d00278664f5a72834ebf0297411564da8b98a75d08eb2c2e9cf706dc985b1`,
its additive-catalog SHA-256 is
`9042968ead33dd098870d21582bc3114706d3af3841bdb3ab7a0d40c5727d990`,
and its canonical report-byte SHA-256 is
`3661d9fe60d78de51bf518fff32282b437b770515c7bbb9a1263072dfb0d13ac`.

The additive seventh tranche is bound by
[reports/executable-seventh-tranche/manifest.json](reports/executable-seventh-tranche/manifest.json).
It admits 20 tasks and 100 bundles from `case-routed-batch-transform` through
exact local types. Its family task-set SHA-256 is
`e68a7e4614424e76fa35d4c0650e500469b971f1a5010d309115b0c225b7b2e6`,
its added-registry SHA-256 is
`14aa05939c2ac2f4954196968003254dee39175f1d1d94e32213b8a74cfff19e`,
its cumulative-suite SHA-256 is
`341b50a83305a9e0c64ada387eee461209ca75d1083e34fe2887a608179de131`,
its additive-catalog SHA-256 is
`99dcf8918151a5a87bdeea8f51bde8ad6e10063b46419a334d7d8b211310e6d8`,
and its canonical 56,368-byte report SHA-256 is
`49c17168813721bc9f66213f4e5b6dd873d97aadd0afd0839a3533a77f7251d9`.

The additive eighth tranche is bound by
[reports/executable-eighth-tranche/manifest.json](reports/executable-eighth-tranche/manifest.json).
It admits 20 tasks and 100 bundles from `collision-safe-batch-rename` through
exact local types. Its family task-set SHA-256 is
`6c563074579359d666faaae2aebf69019c74521e8946cea6a2fe19a756c744cd`,
its added-registry SHA-256 is
`8ef6879c5b6f4198c1b0ff2acfcffe89b6cbdd418a9aa2af2eefedfb12994736`,
its cumulative-suite SHA-256 is
`b22742179e3ce3b7331469de9db0a75ddbae81a3340e2b814c8a7ab34233f0f0`,
its additive-catalog SHA-256 is
`05e4b90408a0970dfded597e5ee7813386bfdaed50a1cea301148eaabd83c297`,
and its canonical
`56,369`-byte report SHA-256 is
`822f2e20e5f73d638dff810c12aec0985145b642801975f6148b034ecf155d0e`.

The additive ninth tranche is bound by
[reports/executable-ninth-tranche/manifest.json](reports/executable-ninth-tranche/manifest.json).
It admits 20 tasks and 100 bundles from `hardlink-deduplicated-mirror` through
exact local types and linear predecessor evidence. Its family task-set,
added-registry, cumulative-suite, cumulative-catalog, discrimination, and
canonical 56,392-byte report SHA-256 values are
`0415daa5f9bccfcd75b621ef4ae71c9e79a5b7c19763ceb470e5ef21169706d1`,
`ff886754b054445a90ad30197d004e4071dba72bf0af17931d05e461c7e90703`,
`d0647e24f29abd59f8c2d6b2ac2a404aee78b92c780f8be4f9b16d200885843b`,
`56932666f2641b5947e1801378b233dd5f37f568e4f2b4c6aa171bad115b09d8`,
`1a0c0d23bb262c1d94250a92574c89af6c6333da08d58be715e1b5d1f4940435`,
and `8bb43dfa235261ab5e237b26a5384d767a02ad351a8b3311fc909ad860b70b6b`.

The additive tenth tranche is bound by
[reports/executable-tenth-tranche/manifest.json](reports/executable-tenth-tranche/manifest.json).
It admits 20 tasks and 100 bundles from
`compressed-archive-roundtrip-verify` through exact local types and
through-ninth predecessor evidence. Its family task-set, added-registry,
cumulative-suite, cumulative-catalog, discrimination, and canonical
56,553-byte report SHA-256 values are
`450ba507f0672e3a47ca6d495a6553d07294c605f94b3c5f03aa111d42bf771a`,
`0d07fd82de275ffd9dc274b97a6fa02fdd0620f83d5ee90a2bea0ad64f06f0ab`,
`629119116c53a0be2cc7cacb5461ae13de7d50f29b0a129707a840089ab48d2f`,
`5a29ea69111028fe69322d892e061a723ab53fb857ce4077cca924e314a4f4d6`,
`ae95eef5802c010e70e338d257f5d0f3d01a39fa5cf471f945a8b75f554faa21`,
and `02442d60bf7d7874016fc9d50857cd49f9d8e1342ece55a42d7c8afcd852f0fb`.

The cumulative 380 specifications and 1,900 fixtures remain public,
development-only, unsealed, unscored, and nonauthorizing; the tenth manifest
explicitly records `independent_human_review_attested: false`. The remaining
120 specifications, independent human review, and a separately reviewed
general-candidate sandbox/supervisor are still required before synthesized-
candidate execution. The current V1 invocation protocol remains intentionally
bound to the first tranche only.

The original allocation remains frozen in
[coverage v1](configs/executable-method-development-coverage-v1.json).
It bound 17 integrated families/340 tasks and 8 planned families/160 tasks to
the 25-family/500-task target. Its semantic coverage SHA-256 is
`6c215d9eaf5581aaa146d6814a9d40621a57459c5af98ae4ca625caff10c9c8c`,
and the canonical config byte SHA-256 is
`46f98f54ef5682ce0adc3854557ecfe8ed092fd5e916935bc27702edb4e86efa`.
The [v2 lock](configs/executable-method-development-coverage-v2.json) is
backward-linked to those exact bytes and binds 18 integrated families/360
tasks plus 7 planned families/140 tasks. The
[migration record](configs/executable-method-development-coverage-v1-to-v2-migration.json)
proves that the hardlink declaration is the only changed family. These locks
remain historical. The
[v3 lock](configs/executable-method-development-coverage-v3.json) preserves
the exact v2 bytes and binds 19 integrated families/380 tasks plus 6 planned
families/120 tasks. The
[v2-to-v3 migration record](configs/executable-method-development-coverage-v2-to-v3-migration.json)
proves that only the archive family was promoted and that its locked axes,
solution track, tools, filesystem schema, output contract, and capability tags
were preserved. The v3 semantic/config-byte SHA-256 values are
`b37f48c98e7216c78ddf74d0ce6f6d74cd095575f20f53de6bf30018b2180d79`
and `de241ad1e4536fa595f99acf0ef05a3e423418876298c576abe87249c018bc0a`
for 23,943 bytes. The migration semantic/config-byte SHA-256 values are
`8e36252576376d86ddb0a4f3b399dfdd66377b0ed026369bbf799edf104818a2`
and `77820327bc105d367d8d737c110e53e8183ce786650ecb4c1699991412cb6683`
for 4,358 bytes. These locks fix allocation metadata only; a planned family is
not implemented, reviewed, sealed, scored, or executable because it appears
in a record. The next planned implementation is `checksum-repair-plan`.

Both third-tranche families require two production-oracle implementations to
agree and have pinned-workspace property verifiers with mutation coverage.
Neither sequential verifier can prove global quiescence, and the compound
family cannot exercise directory permission errors. Both remain public,
unsealed, unscored, and nonauthorizing; catalog admission is not production
approval or human-review attestation.

The separate bulk generated benchmark artifacts remain **semantic
scaffolds**. They contain operator graphs, prompts, split assignments, and
deterministic fixture descriptors. Those descriptors and their generator are
public development scaffolding, not sealed evaluation assets. Unlike the
nineteen concrete cataloged families above, these generated records do not yet
materialize filesystem/process fixtures, reference programs, independent
property checkers, mutation tests, ASTs, or execution traces. In particular,
`sealed_ood` is currently only a reserved split label generated by the same
process as the other splits; it is not yet a held-out compositional-OOD
construction. These artifacts must not be used to claim functional or OOD
pass@1.

A non-executing static audit of
[BashBench](https://arxiv.org/abs/2606.27733) release v1 found that the
released general harness does not establish candidate handoff into its test
scripts, the evaluation and test artifacts do not consistently bind the same
task identities and counts, and the harness source launches tests from host
temporary directories without a sandbox boundary. This is a finding about the
evidence present in the released artifacts, not a claim about an unpublished
evaluator or results from a separately wrapped harness. BashBench is therefore
diagnostic-only and cannot provide independent confirmation until an audited
port supplies explicit candidate handoff, canonical task/result binding,
verifier mutation evidence, and the repository's pinned sandbox and
resource-enforcement guarantees.

The catalog-bound `DevelopmentInvocation` closes the earlier gap between an
arbitrary caller request and one frozen public fixture. Its serialized request
includes model-response and fixture-input bytes because those are required by
a future supervisor, but excludes oracle answer bytes; the public audit record
retains only hashes and counts. The in-process admission and invocation values
remain private trusted-controller handles because they transitively retain the
catalog's oracle bytes; only the framed and audit projections may cross a
candidate boundary. This protocol is not a supervisor and confers no execution
or scoring authority.

Likewise, scored sandbox tooling currently constructs and validates an
argument vector. It does not prove that the selected container daemon is
rootless, pull an image, or execute untrusted code. The generic
public-development namespace/cgroup preflight and catalog-bound candidate
entry point remain nonlaunching. A separate candidate-input-free namespace canary
constructs one narrower transfer request around exactly one snapshot-bound
`/usr/bin/busybox` payload. User-systemd `OpenFile=` is asked to pass its sealed
descriptor to Bubblewrap `--ro-bind-data`; the command applies its mode and a
final root read-only remount without reopening mutable source paths. Its real
runner is wall-time, per-stream-output, memory, PID, open-file, and CPU-quota
bounded and validates an exact response frame.

That canary has no synthesized-candidate or command input parameter and cannot
substitute for the scored container. Its one snapshot payload is nevertheless
executable program bytes. The locally hashed systemd/Bubblewrap/systemctl and
purported BusyBox executables have no external trust or harmlessness attestation, so the
probe's child-behavior and handoff reports remain unverified. It does not prove
the Bash runtime-data/`dlopen` closure, a trusted supervisor/PID1, child
seccomp, a cumulative CPU watcher, candidate output classification,
descendant quiescence, exact-tool policy, or any candidate/scored/claim
authority. The host-side Bash syntax check
is a diagnostic whose executable hash is recorded; scored syntax and execution
must run in the digest-pinned image. Python syntax uses a frozen 3.11 feature
grammar, but is also only a host diagnostic at this stage.

The separate native supervisor lifecycle canary narrows one of those gaps
without opening the candidate boundary. It rebuilds one checked-in static C
supervisor, seals and launches it as namespace PID1, and sends only nine closed
scenario identifiers. Authenticated observations exercise the fixed program's
fork/setsid/zombie cleanup, timeout, cap-plus-one stream classification,
CPU-fan-out reaping, child-only seccomp kill, and resistance to child-emitted
frame-spoof bytes. A user-systemd wrapper requests memory, swap, task, CPU-rate,
NOFILE, core, runtime, and kill-mode controls. The program and launcher are
still locally identified rather than externally trusted, the scenario child is
not Bash, its seccomp policy is not general, cumulative CPU is accounted but
not bounded, and no workspace or tool allowlist is involved. Consequently the
generic candidate executor remains blocked and every execution/scoring/claim
flag remains false.

## Remaining gates before model experiments

- [ ] Add the 120 method-development specifications not yet implemented and
  extend concrete fixture/oracle/reference/verifier coverage across every
  required semantic operator family. Independently review the complete
  development inventory before sealing. The frozen cumulative 380-
  specification suite is public development data and cannot stand in for a
  sealed or scored suite.
- [ ] Pin and audit the container image and utility versions; verify runtime
  resource enforcement on the actual hardware.
- [ ] Complete and pin the Bash runtime-data and `dlopen` closure, externally
  trust the required launcher/runtime executables, and independently validate
  the namespace, descriptor handoff, supervisor, and post-quiescence workspace
  observations. The fixed reviewed case now integrates those seams locally,
  but local content hashes and self-observation are not a production trust
  anchor.
- [ ] Promote the fixed reviewed-program boundary into an externally reviewed
  and trusted general-candidate supervisor: accept only an authenticated
  arbitrary invocation, apply a Bash/runtime-specific allow policy, preserve
  cumulative CPU and quiescence guarantees for all outcomes, enforce the exact
  tool policy, and bind every classified outcome into a scored result. The
  current controller has no candidate input API and establishes resource and
  verification behavior only for one source-reviewed program.
- [ ] Extend verifier mutation tests beyond the nineteen implemented families
  across every remaining semantic family, and complete the stratified human
  audit before sealing test specifications.
- [ ] Requalify any BashBench-derived scored subset through an explicit
  candidate handoff, canonical release-task identity map, independent verifier
  mutation audit, and digest-pinned sandbox port. Keep release v1
  diagnostic-only until all four gates pass, and exclude every harness-audit
  item from scoring.
- [ ] Add typed excluded-task records and an exclusion-manifest loader before
  enabling any exclusion policy other than fail-closed `none`.
- [ ] Add a typed confirmatory bounded-interactive endpoint with the planned
  500 sealed-ID and 250 sealed-OOD counts and its simultaneous
  non-inferiority rule. Current confirmatory evaluation specs are deliberately
  static-primary only.
- [ ] Complete the claim-authorization source chain: reopen and independently
  derive every typed claim-policy projection from the registry-bound outcome,
  completed export and inspection report, token/FLOP ledgers, bounded-terminal
  results, hardware samples, replication registries, and teacher-free corpus
  records. The projection-level evaluator is implemented but intentionally
  cannot authorize a claim.
- [ ] Move sealed evaluator assets out of the public development package and
  add a coarse sealed-result profile that never emits expected-answer counts
  or fixture paths.
- [ ] Require a quiescent candidate workspace and use descriptor-relative,
  no-follow file reads with stability checks so concurrent path replacement
  cannot race artifact or fixture verification.
- [ ] Implement prompt-, AST-, command-graph-, and execution-trace leakage
  reports.
- [ ] Construct, freeze, and audit genuinely held-out compositional-OOD
  operator/schema/output combinations before treating `sealed_ood` as OOD.
- [ ] Implement the fixed static decoder and bounded action loop.
- [ ] Promote raw-ingestion and tokenizer scheduling into a claim-eligible
  data path: promote the implemented lexical prefilter into full row admission
  with Bash AST parsing, execution verification, normalized-prompt ambiguity
  repair, exact/near/program-graph
  decontamination, utility balancing, row-level license resolution, and the
  required audited multiline/stateful generator corpus. The implemented raw
  import and exact schedule remain engineering-only.
- [ ] Add a production dense-model training backend and derive exact FLOP
  accounting from the executed operator trace. A bounded engineering canary is
  not a campaign run.
- [x] Add exact architecture-specific tensor inventory, shape reconstruction,
  model-aware index bounds, GQA compatibility, factorization-tuple binding,
  representable structural-savings checks, and quantization payload lower
  bounds for prospective Qwen2/Qwen3/Llama run specs. This is passive plan
  validation, not completed-artifact evidence.
- [ ] Extend the exact export contracts to residual-branch and hidden-width
  structural compression, physical Qwen2/Llama head compression, hybrid
  architectural-plus-quantization payloads, and quantizer metadata/padding.
  These cases currently reject rather than accepting unproved savings.
- [ ] Add a quantization-calibration profile with its own visible-token ledger
  and corpus provenance. The frozen campaign profiles deliberately require
  optimizer adaptation, so pure PTQ/pruning run specs are diagnostic only.
- [x] Add a narrow, nonauthorizing completed-model evidence companion for exact
  floating-point dense Qwen2/Qwen3/Llama Safetensors. It freshly reinspects the
  source and export, reconstructs both exact dense inventories, validates and
  reconciles saved runtime reports, checks completed identity/accounting and
  the fixed-size or compression rule, and rejects a pruning export that changes
  the wrong architecture dimension. Layer, uniform FFN-width, and uniform
  all-layer Qwen3 complete-GQA-group head-width changes are covered;
  embedding-token completion rejects until derived-map replay exists. The
  companion does not rerun or
  authenticate runtime observations, prove exact selected-unit/value lineage,
  prove training used the pinned bytes, or grant claim authority.
- [ ] Extend completed-model evidence to exporter-specific selected-unit and
  vocabulary-map realization, fresh or externally attested runtime
  name/shape/alias/value graphs, and factorized, quantized, and hybrid formats.
- [ ] Make hardware and evaluation binders reopen and independently derive
  their source evidence before their accounting can enter a research claim.
- [ ] Run the backbone feasibility, capability-support, and signed-transfer
  gates before selecting a specialization or compression operator.

## Research campaign

- [ ] Run the operator funnel at matched target tokens and total FLOPs.
- [ ] Confirm promoted fixed-size and compression arms with fresh paired seeds.
- [ ] Perform causal interventions and protected-capability non-inferiority
  tests.
- [ ] Replicate on the runner-up dense checkpoint and independent terminal
  benchmarks.
- [ ] Export and benchmark portable sub-1B dense artifacts.

The MoE appendix remains disabled unless the explicit sub-1B multi-expert
trigger in the research plan is met.
