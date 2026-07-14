# Capability-Budgeted Dense Specialization for Unix Terminal Models

## Summary and claim boundary

This project studies how to improve executable Unix-terminal performance per
unit of model capacity in dense language models with fewer than one billion
physical parameters. It has two independent confirmatory goals:

1. Improve terminal performance without changing architecture, parameter
   count, serialized precision, or deployed size.
2. Improve the terminal-performance Pareto frontier with respect to physical
   parameters and deployed weight bytes.

The first goal is fixed-size specialization. The second includes structural
compression, vocabulary compression, distillation, and quantization.
Quantization counts as byte and memory compression, not parameter reduction.
Every result must report physical parameters, serialized bytes, average weight
precision, peak memory, and measured inference performance separately; no
single score-per-megabyte ratio will replace the Pareto analysis.

Safety or alignment changes are not successes unless they improve the target
or reduce the deployed footprint. Ability loss is neither required nor
valuable by itself. The words *forget*, *sacrifice*, and *dispensable* may be
used only when an above-floor behavior measurably declines while the target
tradeoff improves. Do not claim certified data deletion.

The final deployed model must be dense and contain fewer than one billion total
physical parameters, including embeddings and output weights. A larger dense
teacher is permitted during training, but its inference and data-generation
cost must be reported. Mixture-of-experts models are excluded from the main
study and may appear only in the triggered appendix defined below.

## Literature verdict and novelty boundary

Search cutoff: **2026-07-14**.

Target-aware specialization and compression are already established:

- [D-Pruner](https://aclanthology.org/2024.findings-naacl.91/) performs
  domain-specific unstructured pruning while preserving general capabilities.
- [TrimLLM](https://aclanthology.org/2025.acl-long.33/) and
  [TALE](https://aclanthology.org/2026.findings-acl.1136/) remove layers for
  target domains or tasks.
- [Cus-Prun](https://aclanthology.org/2025.findings-acl.1201/) extracts smaller
  language-, domain-, and task-specific expert models.
- [MixCal](https://aclanthology.org/2026.eacl-long.347/) uses mixed generic and
  target calibration for specialized pruning and quantization.
- [GISP](https://aclanthology.org/2026.acl-long.1653/) uses global target-loss
  scores to prune heads and MLP channels.
- [TAQ](https://arxiv.org/abs/2511.06516) and
  [TASA](https://arxiv.org/abs/2607.00908) allocate mixed precision using
  task-conditioned sensitivity.
- [LangCompress](https://aclanthology.org/2025.ijcnlp-long.112/) combines
  target-language calibration with vocabulary simplification.
- [UniComp](https://arxiv.org/abs/2602.09130) compares pruning, quantization,
  and distillation and reports capability-dependent compression effects.

Consequently, the project will not claim the first task-aware pruning,
quantization, layer removal, vocabulary trimming, parameter recycling, or
specialization method. The defensible contribution is a preregistered,
execution-grounded study that:

1. Searches for the smallest empirically sufficient capability support set for
   Unix-terminal work.
2. Compares distinct capacity-reallocation and compression operators at matched
   data and compute.
3. Tests whether allowing non-support capabilities to degrade causally improves
   terminal performance or footprint.
4. Produces portable sub-1B dense artifacts and reports actual deployment
   behavior rather than proxy compression alone.

SwiGLU-channel recycling is one candidate, not the starting assumption. A
SwiGLU intermediate channel is an attractive atomic unit because it can be
removed or replaced through matched gate/up rows and a down-projection column,
but there is no prior reason to assume that this granularity dominates layer,
head, hidden-width, vocabulary, low-rank, distillation, or precision choices.
The operator funnel below makes that decision empirically.

If an established method wins, report the comparative result rather than
renaming it. If no method wins, report a null result. Name a new method only if
a preregistered operator or two-operator hybrid beats the strongest close
baseline in fresh confirmation runs.

## Models and feasibility pilot

### Backbone shortlist

Pilot three Apache-licensed dense base checkpoints:

- [`Qwen/Qwen3-0.6B-Base`](https://huggingface.co/Qwen/Qwen3-0.6B-Base)
- [`Qwen/Qwen2.5-0.5B`](https://huggingface.co/Qwen/Qwen2.5-0.5B)
- [`HuggingFaceTB/SmolLM2-360M`](https://huggingface.co/HuggingFaceTB/SmolLM2-360M)

Use
[`Qwen/Qwen2.5-Coder-0.5B-Instruct`](https://huggingface.co/Qwen/Qwen2.5-Coder-0.5B-Instruct)
only as a native-specialist reference. It is not eligible as the primary
backbone because prior code specialization weakens the ability-reallocation
question.

Give each base checkpoint the same terminal data order, optimizer schedule,
and 2M optimizer-visible token micro-SFT. A checkpoint is eligible only if it:

- Reaches 5–80% pass@1 on method-development static tasks.
- Solves at least 10 bounded-terminal development tasks.
- Has at least three audited non-target capability families above behavioral
  floor before terminal post-training.
- Fits the training and deterministic evaluation pipelines without
  architecture-specific correctness exceptions.

Select the model with the highest lower bound of the 95% semantic-task
bootstrap interval for static pass@1. If candidates are within two absolute
points, break the tie by bounded-terminal success and then by smaller BF16
weight bytes. Freeze this choice before operator screening. Repeat promoted
arms on the runner-up; if fewer than two checkpoints are eligible, report the
replication limitation.

### Teacher

Use the dense
[`HuggingFaceTB/SmolLM3-3B`](https://huggingface.co/HuggingFaceTB/SmolLM3-3B)
as the only offline teacher. For each training prompt, generate two candidates
and expand to four only if neither passes. Retain the shortest candidate that:

- Passes every visible training fixture.
- Is syntactically valid.
- Has no serious static-analysis diagnostic.
- Uses only the task's allowed tools.

The teacher may see training prompts and training fixtures, but never sealed
prompts, hidden fixtures, reference solutions, verifier source, or benchmark
failure reports. Distill verified sequences with the student tokenizer. All
comparable arms receive the identical teacher corpus. Report a teacher-free
ablation, but allow the main result to use the teacher.

## Terminal target and data

### Protected Unix-toolbox capability

The target encompasses:

- Bash and POSIX shell syntax, quoting, functions, pipelines, conditionals,
  loops, traps, exit status, and error handling.
- Core file, search, archive, checksum, permission, process, and text utilities.
- `awk`, `sed`, `grep`, `find`, `jq`, regular expressions, JSON, CSV, and
  structured tool output.
- Python 3 standard-library scripting when the task allows it.
- Filesystem and process-state reasoning, including symlinks, permissions,
  races, empty inputs, leading dashes, globs, and unusual filenames.
- English instruction comprehension, control flow, basic numeracy, and error
  interpretation needed to perform those tasks.
- Arbitrary Unicode filenames and file contents even if vocabulary trimming is
  applied.

This is broader than Bash-only synthesis and narrower than a general software
engineering agent. Compilers, package installation, remote services, SSH,
containers, and network access are outside the primary target unless a sealed
task explicitly supplies an offline local substitute.

### Training-source admission

Treat every downloaded corpus as a content-addressed raw import, never as an
automatically eligible training partition.  Before token scheduling, create a
separate curated view with per-row acceptance/rejection reasons, Bash syntax
and positive-tool-policy checks, exact and near deduplication, utility-balance
statistics, and prompt/program-graph decontamination against every evaluation
suite available at that time.  Bind the curated view to the raw-source hashes,
transformation-code hash, policy hash, and evaluation-suite hashes.
Group normalized prompts before admission and reject or explicitly repair
under-specified prompts that map to multiple incompatible programs; report the
collision and per-utility quota histograms rather than counting exact-pair
deduplication as sufficient cleaning.

In particular, NL2SH-ALFA train consists of unverified single-line strings,
contains placeholders and out-of-target utilities, and merges NL2Bash,
LinuxCommands, NL2CMD, InterCode-Bash, and tldr-pages without row-level source
lineage.  Record its repository-level license declaration separately from the
unresolved row-level lineage and component-license map.  Do not call raw rows
executable commands or admit them directly to a claim-bearing run.  The main
target corpus must also include execution-verified, generator-backed
multiline/stateful tasks; raw NL2SH-derived text is at most one audited stratum.

### Static executable suite

Create a generator-backed suite with:

| Split | Specifications |
|---|---:|
| Training | 12,000 |
| Operator selection | 1,000 |
| Method development | 500 |
| Shadow validation | 500 |
| Sealed in-distribution test | 1,000 |
| Sealed compositional-OOD test | 500 |

Each specification must have a distinct normalized operator/dependency graph.
Split jointly by normalized program graph, utility composition, filesystem
schema, Python-versus-shell solution family, and output contract. Report
nearest-neighbor leakage for prompt text, AST, command graph, and execution
trace.

Generate one program per prompt with deterministic decoding. Execute it on at
least five hidden fixtures; the semantic task passes only when every fixture
passes state- and property-based checks. Fixtures must cover spaces, Unicode,
leading dashes, glob characters, empty data, duplicate records, symlinks,
ordering variation, partial failure, and permission errors.

Freeze one response parser before sealed evaluation. Accept raw code or one
optional Markdown code fence. Separately record extraction failure,
truncation, syntax failure, disallowed-tool use, timeout, runtime failure, and
functional failure.

### Bounded interactive suite

Create a second suite with:

| Split | Tasks |
|---|---:|
| Training | 3,000 |
| Operator selection | 500 |
| Method development | 250 |
| Shadow validation | 250 |
| Sealed in-distribution test | 500 |
| Sealed compositional-OOD test | 250 |

Use one fixed agent loop for every model. At each turn the model emits one shell
action through a frozen schema, receives bounded stdout/stderr and exit status,
and may stop with a final answer. Limit each task to eight actions, a fixed
context window, a fixed generated-token budget, and deterministic decoding.
Score final filesystem/process state, not textual resemblance to a reference
trajectory.

The primary endpoint remains static functional pass@1. Bounded-terminal
success is a required external-validity and non-inferiority endpoint, not a
co-primary endpoint.

### Independent diagnostics

- Use [NL2SH](https://aclanthology.org/2025.naacl-long.555/) and NL2Bash as
  exposure-prone command-generation diagnostics.
- Use [BashBench](https://arxiv.org/abs/2606.27733) as an independent static
  executable benchmark after auditing and excluding 50 harness-development
  items.
- Treat [InterCode-Bash](https://intercode-benchmark.github.io/) as
  exposure-prone because NL2SH-ALFA train includes InterCode-Bash lineage.
  It becomes an independent bounded-interaction diagnostic only after an
  exact/fuzzy/program-graph decontamination audit bound to both corpora.
- Run [Terminal-Bench 2](https://arxiv.org/abs/2601.11868) only as a broad floor
  diagnostic. Do not use it for model or method selection because its tasks and
  agent harness extend well beyond the protected target and are likely too hard
  for sub-1B models.

### Execution isolation

Run every scored task in a fresh rootless container with pinned image digest
and utility versions. Disable network, host mounts, the container socket,
setuid, added capabilities, and privilege escalation. Use a read-only root,
isolated writable workspace, fixed UID/GID, locale, timezone, umask, shell
options, PID limit, CPU quota, memory limit, output limit, and timeout.

Validate every verifier with mutation testing, an independently implemented
reference checker, and a stratified human audit of at least 100 tasks before
sealing.

## Capability-support audit

### Candidate families

Protect only the target and prerequisite abilities above. Audit these families
without declaring them irrelevant in advance:

- Korean, Mandarin, and Spanish language use.
- C/C++, Java, JavaScript/TypeScript, and Rust programming.
- SQL execution and database reasoning.
- Advanced mathematics beyond terminal-task numeracy.
- Biomedical, legal, and geographic factual knowledge.
- Creative and long-form prose.

Use executable or objective tests wherever possible, with multiple prompt and
prefix variants. A family is eligible for a sacrifice claim only if the
unmodified selected checkpoint records at least 20 successes on 400 executable
items or scores at least 10 absolute points above chance on a validated
objective benchmark. Behaviors at floor may be reported but cannot count as
forgotten.

### Minimal-support and add-back design

Train an all-retain counterpart and a minimal-support counterpart at identical
target tokens, total tokens, teacher data, optimizer schedule, and FLOPs:

- Both use 80% target data and 20% replay.
- All-retain replay covers every above-floor audited family and the target
  prerequisites.
- Minimal-support replay reallocates the same 20% only among target
  prerequisites; it does not receive extra target tokens.
- KL anchoring, when used, follows the same all-retain versus minimal-support
  boundary.

For each audited family that declines in a winning model, run a one-family
add-back with the same total replay tokens. A family is *dispensable* only if:

1. Its score falls by at least 3 absolute points and 20% relative, with a paired
   interval excluding zero.
2. Static and bounded-terminal scores satisfy their non-inferiority margins.
3. Adding the family back significantly restores its behavior.
4. Restoration either lowers terminal performance at fixed footprint or
   requires a larger artifact to recover the same terminal score.

If target performance improves without measurable ability loss, describe the
result as specialization or compression, not capability sacrifice. If an
ability declines without the add-back tradeoff, describe it as collateral
degradation, not recycled capacity.

## Preregistered operator funnel

Run two paired screening seeds for every configuration. Pair model
initialization, data order, teacher sequences, decoding, task, and fixture. Use
2M optimizer-visible adaptation tokens per screening configuration. Use only
operator-selection and method-development data for promotion, and shadow
validation for checkpoint selection.

Promoted arms receive 20M optimizer-visible tokens and five fresh confirmation
seeds. Repeat promoted winners and their direct baselines on the runner-up
backbone with five fresh seeds. Give each operator one preregistered recipe and
at most three dose points; do not grant the proposed method a larger
hyperparameter budget than a baseline.

### Fixed-size lane

Screen:

1. Ordinary dense terminal SFT with full-capability replay.
2. Dense SFT plus verified sequence distillation.
3. Minimal-support dense SFT plus the identical verified teacher corpus.
4. Target-aware reset/regrow with minimal-support replay.
5. The same selected weights trained from their pretrained values without
   reset.
6. A layer-matched random reset/regrow control.

Before reset/regrow, compare these atomic or grouped units under equal probe
budgets:

- Whole residual branches.
- Attention-head groups compatible with grouped-query attention.
- Deterministic FFN blocks of 64 intermediate channels.
- Hidden-dimension groups that can be exported as a standard dense model.
- Embedding/output token groups.

For each unit group, mask it, apply 16 fixed target look-ahead updates to a
temporary replacement, and measure held-out target improvement over masking
alone while enforcing target-prerequisite constraints. Use cross-fitted data
and require rank stability across both screening seeds.

If FFN blocks win, implement replacement through side tensors: archive the old
rows/columns, mask old activations, initialize fresh gate/up rows and a
zero-initialized down matrix, train the new down matrix for the first 100
steps, then train all replacement matrices. Merge only at export. This is the
only circumstance in which the original SwiGLU-channel mechanism becomes the
main fixed-size candidate.

Promote a fixed-size arm only if it beats the strongest dense matched-compute
baseline by at least 2 absolute development pass@1 points while losing no more
than 2 bounded-terminal points.

### Compression lane

Screen these single-operator families:

1. Task-aware layer removal, with TALE/TrimLLM-style baselines.
2. Global structured attention-head and FFN pruning, with GISP and Cus-Prun
   style baselines.
3. Globally consistent hidden-width reduction.
4. Vocabulary trimming with a derived tokenizer that retains every special
   token and all 256 byte-fallback values.
5. Task-aware mixed-precision weight quantization, with uniform GPTQ/AWQ and
   TAQ/TASA/MixCal-style baselines.
6. Low-rank matrix factorization with dense exported factors.
7. Sequence distillation into a smaller native dense architecture.

Evaluate structural targets near 90%, 75%, and 50% of the original physical
parameters. Evaluate quantization near 8, 4, and 3 average weight bits,
including scales, zero points, codebooks, and padding in serialized-byte
accounting. Report embeddings, output head, attention, FFN, norms, and metadata
separately.

Unstructured and semi-structured sparsity are diagnostic unless a supported
runtime demonstrates smaller resident memory and lower latency using the same
artifact. A nonzero-count proxy alone is not eligible for promotion.

At each development budget, retain nondominated configurations in static
pass@1 versus serialized weight bytes. Break equivalent points by bounded
terminal score, then physical parameters, then measured batch-1 decode
latency. Promote the best single operator. Also evaluate exactly one hybrid:
the best non-quantization architectural operator followed by the best
quantizer. Do not search three-operator combinations.

### Training controls

Use:

- 80% target tokens and 20% replay tokens.
- AdamW with β=`(0.9, 0.95)`, gradient clipping 1.0, 5% warmup, and cosine
  decay. Use epsilon `1e-8`, weight decay `0.1` for every campaign parameter
  group, and FP32 optimizer state.
- Compute causal cross-entropy only on response tokens and each explicit EOS.
  Normalize each optimizer update by its actual supervised-token count,
  including the final partial accumulation; count the separate non-padding
  input-token ledger as optimizer-visible tokens.
- Step warmup/cosine scheduling once per optimizer update. Record the exact
  learning rate, input/supervised token counts, gradient norm, and checkpoint
  hash for every update in a hash-chained ledger.
- Side-only learning rates `{1e-4, 3e-4, 1e-3}` where applicable.
- Full-model learning rates `{1e-5, 3e-5}`.
- BF16 training, packed 1–2k-token sequences, SDPA/FlashAttention where exact,
  and gradient checkpointing where needed.

Report both equal-target-token and equal-total-FLOP contrasts. Include
selection probes, quantization calibration, teacher inference, distillation,
recovery, and hardware conversion in measured compute. A faster or cheaper
method may be reported as such, but compute mismatch cannot support a
performance claim.

Required direct baselines are:

- Original checkpoint and ordinary dense SFT.
- Dense SFT with extra steps matched to total method FLOPs.
- Full-retain and minimal-support replay.
- Uniform quantization at the same average bits.
- Task-agnostic structural pruning at the same architecture size.
- Layer-matched random removal/reset.
- A native smaller dense model at comparable serialized bytes.
- The Qwen coder specialist reference.
- The strongest close established targeted baseline from screening.

## Evaluation and acceptance

### Target and capability metrics

Primary target endpoint:

- Macro-averaged deterministic functional pass@1 over the 1,000 sealed static
  semantic specifications.

Required secondary endpoints:

- Sealed compositional-OOD static pass@1.
- Bounded-terminal semantic success rate.
- Independent NL2SH, BashBench, and InterCode-Bash results.
- Syntax validity, static diagnostics, disallowed-tool rate, timeouts, output
  length, action count, and failure taxonomy.
- Single- versus multi-step tasks and difficulty strata.
- Every above-floor target-support and audited capability family.

Deployment endpoints:

- Total physical and active parameters.
- Serialized artifact bytes and bytes by component.
- Average weight bits including quantization metadata.
- Peak resident memory/VRAM.
- Load, first-token, prefill, and decode measurements from the hardware
  protocol.

### Statistical analysis

- Pair arms by seed, data order, teacher corpus, task, and fixture.
- Bootstrap semantic specifications, nesting fixtures within specification and
  crossing training seed with task.
- Use paired randomization tests for target contrasts.
- Apply Holm adjustment across the two independent confirmatory lane contrasts.
- Freeze decoding, extraction, timeout, rerun, exclusion, checkpoint, and
  analysis policies before opening sealed data.
- Run each sealed suite once after method and analysis lock.

The lanes are independently confirmatory: either may succeed while the other
is reported as a null.

Fixed-size success requires all of:

1. At least +3 absolute sealed static pass@1 points over the strongest
   matched-data, matched-FLOP dense baseline.
2. Holm-adjusted lower confidence bound above zero.
3. Identical architecture, physical parameters, serialized precision, and
   artifact bytes within metadata tolerance.
4. Bounded-terminal decline no greater than 2 points under a simultaneous
   non-inferiority interval.
5. Replication on the runner-up backbone and the independent static and
   interactive benchmarks.

Compression success requires all of:

1. Either at least 25% fewer serialized bytes with static non-inferiority within
   1 point, or at least +3 static points at matched serialized bytes.
2. At least +3 static points over the strongest task-agnostic compression
   baseline at comparable bytes, with adjusted lower bound above zero.
3. Bounded-terminal decline no greater than 2 points under a simultaneous
   non-inferiority interval.
4. A measured peak-memory reduction.
5. Replication on the runner-up backbone and independent benchmarks.

An architectural compression claim additionally requires at least 20% fewer
physical parameters. A quantization-only winner is a valid
deployment-footprint result but must not be described as a smaller-parameter
network. RTX 5090 latency is descriptive, not a portable success condition.

### Interpretation rules

- Random reset matches selected reset: generic regularization or plasticity.
- No-reset tuning matches reset/regrow: parameter-efficient specialization,
  not capacity recycling.
- Minimal-support dense SFT matches the structured method: selective replay or
  ordinary specialization explains the result.
- Uniform quantization matches target-aware quantization: no evidence that
  capability-aware bit allocation matters.
- Vocabulary trimming wins alone: lexical/output capacity, not FFN capacity,
  was the useful tradeoff.
- Target improves without audited ability loss: specialization, not
  sacrifice.
- Ability loss has no add-back mediation: collateral degradation.
- No above-floor capability can be dropped beneficially: a null result against
  the capability-competition premise.

## Reproducibility interfaces

The implementation must expose manifest-driven `prepare`, `train`, `compress`,
`evaluate`, `bench-hardware`, and `merge-results` commands. The concrete CLI
may be Python, but each command must consume an immutable YAML or JSON manifest
and write machine-readable outputs without hidden defaults.

Experiment manifests must contain:

- Model repository and immutable revision.
- Tokenizer revision and any derived-vocabulary mapping.
- Data, semantic-graph, fixture, and split hashes.
- Container image digest and verifier revision.
- Target/support capability mixture and teacher provenance.
- Operator, structural indices, dose, bit allocation, and archived weights.
- Optimizer settings, seeds, token counts, measured FLOPs, and checkpoint rule.
- Export format, runtime compatibility, and artifact hashes.

Per-task outputs must retain the prompt identifier, generated text hash,
extraction result, syntax result, tool-policy result, fixture outcomes,
resource use, action trace, and terminal status. Sealed prompt text and fixtures
must remain outside training manifests.

## Portable hardware protocol

Use the RTX 5090 as the controlled development device, not as evidence of
portable speed. A sub-1B model may be too small to saturate it, so record GPU
utilization and separate CPU tokenization, launch overhead, prefill, and decode.

The complete cross-device procedure is in [HARDWARE.md](HARDWARE.md), and every
result must validate against
[hardware-result.schema.json](hardware-result.schema.json). At minimum measure:

- Five cold process starts for artifact load time.
- Ten warmup iterations followed by 30 measured repetitions.
- Batch size one.
- Token-controlled prefill at 128, 512, and 2,048 tokens.
- Token-controlled decode at 64 and 256 generated tokens.
- A fixed real-terminal prompt subset.
- Median and p95 first-token latency, prefill throughput, decode throughput,
  wall time, peak device memory, and peak host RSS.

Compare models only within the same engine, backend, compiler flags, precision
path, and power state. Custom-kernel results form a separate runtime stratum.
Later Intel iGPU, AMD APU, and CPU runs must reuse the exact artifact and
workload hashes where the backend supports them. Until those results exist,
state explicitly that latency conclusions are RTX-5090-specific and may reverse
on memory-bandwidth-limited or shared-memory devices.

## Triggered sub-1B expert appendix

Do not implement an MoE arm during the main campaign. Trigger it only if dense
experiments reveal at least two capability clusters whose selected component
masks reproduce across seeds, have within-cluster Jaccard overlap at least
0.50, and cross-cluster overlap no greater than 0.25.

Any triggered expert model must:

- Remain below 1B total physical parameters including shared weights, every
  expert, router, embeddings, and output head.
- Contain at least two experts with distinct evaluated capability families.
- Route held-out family labels with at least 80% accuracy without being given
  the label explicitly.
- Lose at least 5 points on an expert's own family and no more than 2 points on
  other families when that expert is ablated.
- Beat an equal-total-parameter dense baseline on the target-versus-footprint
  frontier.

If any condition fails, report the exploratory result without claiming
meaningfully separate expertise.

## Campaign order

1. Build generators, containers, response parsers, verifiers, manifests, and
   the portable hardware harness.
2. Validate leakage controls, mutation tests, reference checkers, and human
   audit; then seal evaluation data.
3. Run the three-backbone feasibility pilot and freeze the primary and
   runner-up.
4. Establish dense SFT, teacher-distillation, native-specialist, and
   task-agnostic compression baselines.
5. Run the two-seed fixed-size and compression operator funnels.
6. Freeze one promoted arm per lane and at most one two-operator hybrid.
7. Train five fresh confirmation seeds, run capability add-backs, and replicate
   on the runner-up backbone.
8. Lock methods and analysis, open sealed suites once, then run independent
   benchmarks.
9. Benchmark artifacts on the RTX 5090 and export the portable bundle for later
   laptop, Intel iGPU, AMD APU, and CPU measurements.
10. Consider the expert appendix only if its preregistered trigger fires.

Actual wall time must be recalibrated after the backbone pilot and first
2M-token screening run. No positive result may be inferred from the schedule,
and no sealed evaluation may be repeated to repair an unfavorable outcome.
