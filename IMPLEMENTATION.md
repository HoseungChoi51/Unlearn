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
- [x] Content-addressed method-development coverage lock for exactly 25
  families, 20 tasks per family, and 500 tasks total. The canonical 4-by-5
  parameter grids bind each family's lifecycle state, Bash-native or
  Python-permitted solution track, allowed tools, filesystem schema, output
  contract, and capability tags. It reconciles 14 integrated families/280
  tasks to all five live cumulative registry identities and reserves 11
  concrete families/220 tasks without pretending that planned entries have
  fixtures or verifiers. The config is public, unsealed, unscored,
  nonauthorizing, and records no independent human-review attestation.
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

The cumulative 280 specifications and 1,400 fixtures remain public,
development-only, unsealed, unscored, and nonauthorizing; the fifth manifest
explicitly records `independent_human_review_attested: false`. The remaining
220 specifications, independent human review, and a separately reviewed
general-candidate sandbox/supervisor are still required before synthesized-
candidate execution. The current V1 invocation protocol remains intentionally
bound to the first tranche only.

The complete allocation is frozen separately in
[configs/executable-method-development-coverage-v1.json](configs/executable-method-development-coverage-v1.json).
It binds 14 integrated families/280 tasks and 11 planned families/220 tasks to
the 25-family/500-task target. The semantic coverage SHA-256 is
`b7829f8e2b45ce94c0a9debae8fd005bc5e1d60d2533b02136e1c642661da8c4`,
and the canonical config byte SHA-256 is
`a645372249292b323d9eed093a29026d8918a378d8441e096d9273d08d54f4e6`.
This lock fixes allocation metadata only; a planned family is not implemented,
reviewed, sealed, scored, or executable because it appears in the record. The
next planned implementation is `bounded-retry-state-machine`.

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
fourteen concrete cataloged families above, these generated records do not yet
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

- [ ] Add the 220 method-development specifications not yet implemented and
  extend concrete fixture/oracle/reference/verifier coverage across every
  required semantic operator family. Independently review the complete
  development inventory before sealing. The frozen cumulative 280-
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
- [ ] Extend verifier mutation tests beyond the fourteen implemented families
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
