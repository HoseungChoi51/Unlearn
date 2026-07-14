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
- [x] Four public-development static verifier families: the original
  active-label JSONL vertical slice plus copy-map, CSV-totals, and
  checksum-mode. They use deterministic edge-case fixtures, descriptor-only
  metadata suitable for an isolated trusted harness, separate in-module
  reference-construction paths, semantic final-state/property
  verification, no-follow descriptor-relative fixture materialization, and
  mutation/race tests. They never execute candidate code and are not sealed
  evaluation assets.
- [x] Dependency-free, read-only local Safetensors artifact inspection with
  strict JSON and shard-layout validation, no-follow stable reads, resource
  ceilings, domain-separated bundle/weight/tokenizer identities, stored tensor
  element/byte/component accounting, and conservative dense/MoE evidence.
- [x] Optional, local-only causal-LM runtime qualification for statically
  accepted flat Safetensors bundles. It rejects custom code, performs one
  bounded non-generative finite-logit forward pass, rechecks artifact
  stability, and reports exact physical and trainable storage spans while
  counting tied/shared storage once. This is runtime compatibility evidence,
  not architecture completeness or model-quality evidence.
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

The bulk generated benchmark artifacts are currently **semantic scaffolds**.
They contain operator graphs, prompts, split assignments, and deterministic
fixture descriptors. Those descriptors and their generator are public
development scaffolding, not sealed evaluation assets. Unlike the four narrow
public-development verifier families above, these generated records do not yet
materialize filesystem/process fixtures,
reference programs, independent property checkers, mutation tests, ASTs, or
execution traces. In particular, `sealed_ood` is currently only a reserved
split label generated by the same process as the other splits; it is not yet a
held-out compositional-OOD construction. These artifacts must not be used to
claim functional or OOD pass@1.

Likewise, sandbox tooling currently constructs and validates an argument
vector. It does not prove that the selected container daemon is rootless, pull
an image, or execute untrusted code. Preflight can establish whether a local
runtime is eligible for a separately reviewed benign canary, but it does not
execute that canary, prove writable cgroup delegation, or prove enforcement.
It rehashes the runtime executable after its probes; a future fd-bound launcher
would be needed to exclude an adversarial swap-and-restore race. The host-side
Bash syntax check is a
diagnostic whose executable hash is recorded; scored syntax and execution must
run in the digest-pinned image. Python syntax uses a frozen 3.11 feature
grammar, but is also only a host diagnostic at this stage.

## Remaining gates before model experiments

- [ ] Materialize executable fixture families and independent property/state
  verifiers for every semantic operator family.
- [ ] Pin and audit the container image and utility versions; verify runtime
  resource enforcement on the actual hardware.
- [ ] Implement and test the trusted runtime canary, outer wall-clock watchdog,
  CPU-time enforcement, and explicit output-overflow classification. The
  current sandbox argv has no `cpu_time_seconds` mechanism and output capping
  alone cannot prove a `resource_limit` outcome.
- [ ] Complete verifier mutation tests across every semantic family and the
  stratified human audit before sealing test specifications.
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
- [ ] Add dataset ingestion, tokenizer provenance, dense-model training, and
  exact FLOP accounting backends.
- [ ] Add architecture-specific tensor inventory and shape reconstruction and
  completed-record binding for opened inspection/runtime reports. Generic
  runtime loading and exact physical/trainable storage accounting are now
  implemented; neither proves architecture-specific checkpoint completeness,
  logical parameter count, or a valid sub-1B export without the remaining
  source binding.
- [ ] Add architecture-specific model-aware bounds and GQA compatibility
  checks for the existing typed structural-index, factorization, and
  quantization-allocation operator payloads.
- [ ] Add a quantization-calibration profile with its own visible-token ledger
  and corpus provenance. The frozen campaign profiles deliberately require
  optimizer adaptation, so pure PTQ/pruning run specs are diagnostic only.
- [ ] Make the completed-record binder open and validate the model inspection
  reports rather than only requiring exact source/export report digests. Do the
  same for hardware and evaluation artifact bindings before using their
  accounting as research evidence.
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
