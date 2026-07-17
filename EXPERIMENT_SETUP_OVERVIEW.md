# Experiment setup overview

This document is the short orientation to the experiment: what the major
components are, why each one is necessary, and what evidence it must produce.
The detailed component reference is
[EXPERIMENT_COMPONENTS.md](EXPERIMENT_COMPONENTS.md); the full scientific
design is [PLAN.md](PLAN.md), and current implementation status is
[IMPLEMENTATION.md](IMPLEMENTATION.md).

The central question is deliberately narrow:

> Can a dense language model with fewer than one billion physical parameters
> do Unix-terminal work better at the same deployed size, or preserve useful
> terminal performance at a smaller deployed size?

Forgetting is not the objective. A lost ability matters only when its removal
causes a measured target gain or a real deployment saving. Safety-only behavior
changes and ability suppression at unchanged performance and size do not count.

## The setup in one view

| Component | Role in the experiment | Why it matters |
|---|---|---|
| Claim contract | Separates fixed-size specialization from compression | Prevents a larger, lower-precision, or merely suppressed model from being described as a capacity improvement |
| Dense model boundary | Counts every physical parameter and deployed byte | Prevents nominal sparsity, shared weights, or hidden routing capacity from evading the sub-1B limit |
| Target and support map | Defines terminal ability and measures which other abilities support it | Prevents intuition-based removal of Python, structured data, reasoning, or other knowledge that Bash actually uses |
| Feasibility gates | Requires target headroom and above-floor candidate abilities | Prevents floor and ceiling effects from deciding the result before the intervention is tested |
| Admitted training data | Supplies licensed, correct, decontaminated, reproducible examples | Prevents leakage, invalid commands, and duplicated templates from masquerading as model improvement |
| Matched training ledger | Equalizes target tokens, replay, updates, and compute | Prevents one arm from winning because it quietly received more optimization |
| Semantic benchmark | Tests executable behavior over distinct program graphs and hidden fixtures | Prevents surface similarity or memorized command text from being mistaken for terminal competence |
| Evaluation lifecycle | Separates development, checkpoint selection, and sealed final tests | Prevents repeated test inspection from turning the final benchmark into training data |
| Parser and decoding contract | Converts one model response into one candidate deterministically | Prevents extraction tweaks, reruns, and token-limit changes from moving the score |
| Sandbox and supervisor | Runs untrusted code with pinned tools, isolation, limits, and quiescence | Prevents host dependence, escapes, surviving children, and post-timeout mutation from corrupting evaluation |
| Oracle and verifier | Independently derive expected semantics and inspect the complete final state | Prevents shared bugs and string-matching shortcuts from awarding false passes |
| Operator funnel | Compares dense tuning, structural interventions, distillation, and task-aware compression | Prevents the study from assuming in advance that SwiGLU channels, or any other unit, are optimal |
| Baselines and interventions | Separate selective reallocation from extra compute, generic plasticity, and ordinary sparse tuning | Makes a positive result causally interpretable instead of merely correlational |
| Protected and add-back tests | Measure collateral damage and whether the sacrificed ability mediates the gain | Prevents broad degradation from being sold as useful specialization |
| Confirmation and statistics | Use fresh seeds, paired tasks, corrected intervals, and non-inferiority gates | Prevents a lucky seed or selected metric from becoming the headline result |
| Provenance and deployment | Bind every input and output, then measure real memory, latency, and throughput | Prevents irreproducible scores and nominal compression that provides no runtime benefit |

## How the components depend on one another

```text
claim and model boundary
          |
          v
target/support map + feasibility gates
          |
          v
admitted data + matched training ledger
          |
          v
operator screening + matched controls
          |
          v
frozen parser -> isolated execution -> semantic verification
          |
          v
fresh-seed confirmation + paired statistics
          |
          v
reproducible artifact + deployment measurements
```

This order is substantive, not administrative. Training before benchmark
sealing risks leakage. Scoring before runtime isolation makes results depend on
the host. Choosing an operator before capability audits can remove useful
support. Reporting compression before exporting and measuring the artifact can
confuse a paper parameter count with a deployable saving.

## 1. Claim and model boundary

The experiment has two measurement lanes. Fixed-size specialization holds the
architecture, physical parameter count, numerical format, and deployed weight
bytes constant while asking for higher terminal accuracy. Compression asks for
a better accuracy-versus-footprint frontier and reports parameters, bytes,
precision, peak memory, latency, and throughput separately.

The primary study is dense and non-MoE. An expert-model appendix is eligible
only if the complete network remains below one billion physical parameters and
routing plus ablation demonstrate meaningfully distinct expertise. Architecture
labels alone are not evidence of separate experts.

## 2. Target, support, and sacrifice candidates

Terminal work is broader than Bash syntax. It depends on Unix concepts, text
processing, regex, Python scripting, JSON/YAML/CSV handling, English
instructions, algorithms, and numeracy. These abilities form the protected
support set until experiments show otherwise.

Candidate abilities are audited rather than guessed. Each must begin above a
behavioral floor, show reproducible neutral or negative transfer to the target,
and survive cross-fitted measurement. A sacrifice is scientifically useful
only if the target or footprint improves, matched nonselected abilities are
preserved, and restoration or add-back moves the result in the predicted
direction.

## 3. Data and training accounting

A content hash establishes identity, not fitness for training. Data admission
also checks licensing, command correctness, ambiguity, duplicate structure,
coverage balance, and contamination against every known evaluation suite.
Teacher-generated programs, when used, must pass the same executable checks
and be shared across comparable arms.

Token schedules and optimizer ledgers count non-padding and supervised tokens,
updates, replay, and measured compute. The study reports both equal-target-token
and equal-total-compute comparisons so selection or look-ahead work cannot be
treated as free.

## 4. Benchmark and evaluation boundary

The benchmark is generator-backed and split by semantic program structure,
filesystem schema, utility composition, and output contract. A single generated
program must pass every hidden fixture for its specification. Edge profiles
cover filenames and states that frequently expose brittle shell solutions.

The response parser, decoding limits, failure taxonomy, and rerun policy are
frozen before final evaluation. Candidate code then runs with pinned tools in
an isolated workspace under a trusted supervisor. An independent oracle and
property verifier inspect output plus the complete final filesystem state.
Mutation testing and human review address checker blind spots that ordinary unit
tests cannot establish.

## 5. Method selection and causal controls

The operator funnel first asks which intervention granularity actually improves
the target/size frontier. It includes ordinary dense tuning, replay and
distillation changes, structured pruning, width or layer reduction, vocabulary
changes, factorization, task-aware quantization, and reset/regrow at multiple
structural units. SwiGLU-channel recycling remains one candidate, not the
premise.

Matched controls include extra-compute dense tuning, random intervention,
target-only plasticity selection, no-reset sparse tuning, task-agnostic pruning
or quantization, and natively smaller dense models. Swap-back, re-zero,
capability add-back, and attribution tests determine whether a sacrificed
ability and the replacement capacity actually mediate any gain.

## 6. Confirmation, provenance, and deployment

Screening results only nominate methods. Confirmation uses fresh training
seeds, paired task/data order, a runner-up dense backbone, independent
benchmarks, predeclared intervals, multiple-comparison correction, and
protected-capability non-inferiority tests. The sealed suite is opened once,
after the method and analysis are locked.

Immutable manifests bind model revisions, data, task graphs, fixtures, masks,
seeds, ledgers, outputs, and exported artifacts. Every consumer must reopen and
validate its inputs rather than trust copied hashes. Compression claims also
require portable hardware measurements from the exact exported artifact.

## Present state

The repository has not produced a model-quality result. It currently provides
contracts, data and training canaries, model/runtime inspection, and public
method-development benchmark infrastructure. The benchmark allocation is
locked at 25 families and 500 tasks; 23 families/460 tasks and 2,300 fixture
bundles are implemented across fourteen additive tranches. Two families/40
tasks remain, beginning with `process-lifecycle-delta`. The current
coverage lineage promotes only one frozen family per version and proves the
other 24 family records unchanged. Earlier coverage versions remain immutable
historical records.

These public assets are unsealed, unscored, and not authorized for candidate
execution, model selection, or scientific claims. They reduce implementation
risk and make later evidence interpretable; they do not demonstrate that a
specialization or compression method works.

The ninth tranche and its v1-to-v2 coverage correction are explained in
[HARDLINK_EXPERIMENT_INFRASTRUCTURE.md](HARDLINK_EXPERIMENT_INFRASTRUCTURE.md).
The tenth tranche, its bounded semantic codec/archive verifier, reviewed Bash
canary, and v2-to-v3 promotion are explained in
[ARCHIVE_ROUNDTRIP_EXPERIMENT_INFRASTRUCTURE.md](ARCHIVE_ROUNDTRIP_EXPERIMENT_INFRASTRUCTURE.md).
The eleventh tranche, strict manifest parsing, declarative repair-plan
semantics, reviewed Bash canary, and v3-to-v4 promotion are explained in
[CHECKSUM_REPAIR_EXPERIMENT_INFRASTRUCTURE.md](CHECKSUM_REPAIR_EXPERIMENT_INFRASTRUCTURE.md).
The twelfth tranche, strict mixed-codec parsing, multiplicity-preserving join,
missing-field policies, reviewed Bash canary, and v4-to-v5 promotion are
explained in
[JSONL_CSV_ENRICHMENT_EXPERIMENT_INFRASTRUCTURE.md](JSONL_CSV_ENRICHMENT_EXPERIMENT_INFRASTRUCTURE.md).
The thirteenth tranche, strict versioned nested JSON, exact migration policies,
source-reviewed Python-permitted canary, and append-only evidence are explained in
[NESTED_JSON_SCHEMA_MIGRATION_EXPERIMENT_INFRASTRUCTURE.md](NESTED_JSON_SCHEMA_MIGRATION_EXPERIMENT_INFRASTRUCTURE.md).
The fourteenth tranche, strict dependency-graph codecs, deterministic Kahn
policies, exact cycle classification, and append-only evidence are explained
in
[DEPENDENCY_DAG_EXECUTION_PLAN_EXPERIMENT_INFRASTRUCTURE.md](DEPENDENCY_DAG_EXECUTION_PLAN_EXPERIMENT_INFRASTRUCTURE.md).
