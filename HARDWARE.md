# Portable Hardware Benchmarking Guide

## Purpose

This protocol measures deployment behavior without confusing model changes with
runtime or hardware changes. The RTX 5090 is the first controlled development
device. Its results establish correctness and a local comparison, but they do
not establish that the same ranking holds on a CPU, Intel integrated GPU, AMD
APU, or another inference engine.

Every recorded run must validate against
[`hardware-result.schema.json`](hardware-result.schema.json). Keep raw timing
samples alongside the validated summary even though only the summary is
portable across repository versions.

## Comparison rules

1. Compare artifacts only within a **runtime stratum**: the same engine,
   engine revision, backend, compiler flags, thread count, offload policy,
   context configuration, and power mode.
2. Use the exact same artifact bytes when comparing machines. If conversion is
   necessary, the converted artifact starts a new stratum and receives a new
   SHA-256 digest.
3. Never compare a custom-kernel method against a baseline running through a
   slower generic engine. Re-run the baseline in the custom runtime or report
   the results separately.
4. Report physical parameters, active parameters, serialized weight bytes,
   average weight bits, host RSS, and device memory separately.
5. Quantization metadata, padding, scales, zero points, codebooks, tokenizer,
   and required auxiliary files count toward the deployable bundle. Report
   weight bytes separately from the complete bundle bytes.
6. Use batch size one for the primary latency result. Optional throughput runs
   with larger batches must be labeled secondary.
7. Do not pool measurements across devices. Merge manifests for display and
   analysis, but retain one hardware-specific estimate per stratum.

## Artifact bundle

Freeze one bundle before benchmarking:

- Model weights and all required quantization metadata.
- Tokenizer and any restricted-vocabulary mapping.
- Model configuration and generation configuration.
- Experiment manifest and source checkpoint revision.
- A SHA-256 manifest covering every bundle file.
- Fixed token-controlled workloads.
- Fixed real-terminal prompts and their public, non-sealed identifiers.
- Expected deterministic token hashes for a short correctness smoke test.

Do not place sealed prompts, fixtures, verifier code, or reference programs in
the portable bundle. The real-terminal workload should be a frozen public or
development subset that is never used for model selection after hardware
results are observed.

## Runtime strata

Use at least these strata when supported:

### Native model runtime

Use the training/evaluation framework's standard inference path for BF16 and
custom structural or mixed-precision artifacts. This stratum establishes that
the exported model is correct and measures the method in its intended runtime.

### Portable runtime

Use a single portable engine and artifact format for uniform quantization and
all structurally modified models it supports. A GGUF-capable engine is a
practical choice because the same artifact can often run through CUDA, CPU,
Vulkan, or SYCL backends, but backend availability must be verified on each
machine rather than assumed.

Record unsupported model/backend combinations as `unsupported`; do not replace
them silently with another engine.

## Environment capture

Capture this information before every benchmark session:

- Repository revision and dirty-worktree state.
- Artifact, tokenizer, workload, and experiment-manifest hashes.
- Operating system, kernel, hostname hash, and container image when used.
- CPU model, physical cores, logical threads, NUMA layout, and system RAM.
- Accelerator name, driver, firmware/runtime version, and visible memory.
- Engine name, exact revision, backend, compiler, build flags, and linked math
  libraries.
- Thread count, affinity, device offload, KV-cache precision, context size, and
  memory-mapping policy.
- Power profile, power limit, clock policy, laptop AC/battery state, and cooling
  mode.
- Starting and ending temperatures and any observed thermal or power
  throttling.
- Other processes using meaningful CPU, accelerator, or memory capacity.

Use an anonymized stable machine identifier in published records. Keep the
hostname only in private raw logs.

## Correctness gate

Before collecting performance data:

1. Load the artifact in the selected runtime.
2. Confirm model parameter and serialized-byte accounting against the export
   manifest.
3. Tokenize the fixed smoke prompts and record token counts.
4. Generate deterministically with temperature zero and the frozen stop rules.
5. Compare generated token hashes and executable outcomes with the artifact's
   reference run. Exact token equality is required when the runtime promises
   numerically equivalent execution; otherwise executable outcome equality is
   required and token divergence is reported.
6. Run a Unicode filename, byte-fallback, empty-input, and long-context smoke
   case.

Do not benchmark an artifact that fails the gate. Record the failure as a
correctness result rather than a latency result.

## Workloads

### Token-controlled microbenchmarks

Use deterministic token sequences that are valid for the artifact's tokenizer.
Record actual token counts after tokenization.

| Workload | Prompt tokens | Generated tokens | Repetitions |
|---|---:|---:|---:|
| Short prefill/decode | 128 | 64 | 30 |
| Medium prefill/decode | 512 | 64 | 30 |
| Long prefill/decode | 2,048 | 64 | 30 |
| Short long-decode | 128 | 256 | 30 |
| Medium long-decode | 512 | 256 | 30 |

The primary batch size is one. Use the same KV-cache precision across a stratum.
Measure prefill and decode separately when the engine exposes the split. When
it does not, record end-to-end wall time and mark split metrics unavailable.

### Real-terminal workload

Use a frozen, stratified set of 100 non-sealed prompts:

- 50 single-program synthesis prompts.
- 25 short bounded-terminal tasks expected to finish in at most three actions.
- 25 longer bounded-terminal tasks allowed up to eight actions.

Run deterministic generation once per prompt per seed. Report prompt tokens,
generated tokens, actions, executable success, first-token latency, total model
time, tool time, and end-to-end task time. Tool/container time must not be
included in model decode throughput.

The real workload detects tokenization, stopping, and variable-output effects
that token-controlled tests intentionally remove. Do not substitute it for the
sealed model-quality evaluation.

## Measurement procedure

### Cold load

Run five independent processes after the operating system has reached a stable
idle state. Record process start to model-ready time, peak host RSS, peak device
memory, and whether filesystem pages were already cached. Do not claim a true
cold-disk measurement unless caches were controlled and that intervention is
documented.

### Warm inference

For every token-controlled workload:

1. Start one process and load the model.
2. Execute 10 unmeasured warmup iterations.
3. Confirm no compilation, graph capture, or memory allocation remains pending.
4. Execute 30 measured iterations in a randomized workload order.
5. Synchronize the accelerator around timed regions.
6. Store every raw sample.
7. Report sample count, median, p95, minimum, and maximum.

Measure:

- First-token latency in milliseconds.
- Prefill tokens per second.
- Decode tokens per second.
- End-to-end wall time.
- Peak host RSS and peak device memory.
- Mean accelerator utilization when available.
- Energy per request when a sufficiently sampled device counter is available;
  otherwise record `null` rather than estimating it.

Reset peak-memory counters before each workload. Use steady-state allocated
memory rather than framework-reserved memory when both are available, and
record both in raw logs.

## RTX 5090 development run

The 5090 can hide differences in sub-1B models through kernel-launch,
tokenization, Python, and synchronization overhead. Therefore:

- Run both the native and portable strata where possible.
- Record accelerator utilization and CPU model time.
- Keep batch size one as the headline result.
- Report prefill and decode separately.
- Include at least the BF16 original, dense post-trained baseline, uniform
  quantization baseline, task-aware winner, structural winner, and promoted
  hybrid.
- Treat differences smaller than run-to-run variation as ties.
- Phrase every latency conclusion as specific to the recorded engine and 5090
  configuration.

Do not use the 5090 latency ranking to select the research method. Method
selection uses target quality and footprint; hardware results characterize the
frozen artifacts afterward.

## Later CPU, Intel iGPU, and AMD APU runs

Run these only after the model structure and export format are stable.

### CPU baseline on every machine

Run the portable artifact with three thread settings:

1. One thread.
2. One thread per physical core.
3. All logical threads.

Pin threads when the operating system and engine support it. Record affinity,
memory channel configuration, instruction-set path, and whether weights are
memory-mapped. The physical-core result is the primary CPU comparison unless a
different setting is consistently faster across all frozen workloads.

### Intel integrated GPU

Attempt the portable engine's supported Intel accelerator backends in the
documented order for that engine version. Record the backend actually selected;
some runtimes fall back to CPU without failing. Verify device utilization and
offload in the log before labeling a result `intel_igpu`.

Because integrated graphics use shared system memory, report process RSS,
shared device allocation, and total system-memory pressure. A device-memory
field alone is insufficient.

### AMD APU

Attempt the portable engine's supported AMD accelerator backend, then record a
CPU-only run with the identical artifact. Verify that kernels execute on the
GPU and record UMA allocation, memory speed, driver, and power profile. Keep
Vulkan, ROCm, and CPU results in distinct runtime strata if more than one is
available.

### Thermal control

Laptop and mini-PC rankings can change as devices heat up. Begin after a stable
idle period, record initial temperature, randomize model order, and record final
temperature and throttling. Repeat the complete model order in reverse once.
If the two orderings disagree beyond sampling uncertainty, report both rather
than averaging away the thermal effect.

## Result validation and merge

Each summary JSON must:

- Validate against the repository schema.
- Reference immutable artifact and workload hashes.
- Contain exactly one machine, runtime stratum, and workload.
- Retain `null` for unsupported measurements.
- Link to raw samples through `raw_samples_sha256`.
- State correctness-gate status.

The future `merge-results` command must reject duplicate `run_id` values,
schema-version mismatches, hash mismatches, and summaries whose sample count
does not match the protocol. It may aggregate repeated sessions on the same
stratum, but it must never pool samples across hardware or runtimes.

## Reporting checklist

- [ ] Artifact and bundle hashes match across machines.
- [ ] Correctness gate passes.
- [ ] Engine, backend, build, threads, offload, and power state are recorded.
- [ ] Five cold starts are separate from warm inference.
- [ ] Ten warmups and 30 measured repetitions are complete.
- [ ] Raw samples and validated summaries are retained.
- [ ] Batch-1 token-controlled and real-terminal workloads are both present.
- [ ] Host and device/shared memory are reported.
- [ ] Tool execution time is separated from model time.
- [ ] Thermal and throttling observations are recorded.
- [ ] Claims are restricted to the tested hardware/runtime strata.
