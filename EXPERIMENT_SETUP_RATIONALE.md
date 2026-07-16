# Why the experiment is built this way

This document is the short, research-level explanation of the experiment
setup. It answers three questions for each major component:

1. What uncertainty does the component resolve?
2. Why is that uncertainty important to the main claim?
3. What conclusion becomes invalid if the component is missing?

It is a claim-and-failure-mode summary. The more detailed operational role of
each component is covered in
[EXPERIMENT_COMPONENTS.md](EXPERIMENT_COMPONENTS.md).

The authoritative protocol and thresholds remain in [PLAN.md](PLAN.md), while
[IMPLEMENTATION.md](IMPLEMENTATION.md) is the live build-status ledger. This
document deliberately avoids treating implemented infrastructure, passing
canaries, or a completed benchmark family as evidence that a model method has
already worked. There is no model-quality result yet.

## The central question

The project asks whether a **dense, non-MoE language model below one billion
physical parameters** can become better at Unix-terminal work in either of two
ways:

- **fixed-size specialization:** improve executable terminal performance with
  identical deployed architecture, physical parameter count, serialized
  precision, and artifact bytes within metadata tolerance; or
- **compression:** preserve enough terminal performance in a genuinely
  smaller or lower-cost artifact to improve the performance/footprint
  frontier.

Forgetting is not the objective. Losing an ability is useful only if it causes
or enables one of those two outcomes. Safety alignment or behavioral
suppression does not count when target performance and deployment size remain
unchanged. Capability-aware quantization is therefore as relevant as
reset/regrow or pruning if it improves the measured frontier.

The main study excludes MoE architectures. A sub-1B expert appendix is allowed
only if the dense experiments first reveal reproducible capability clusters
and the complete expert network—including all experts, shared weights, router,
embeddings, and output head—stays below the same physical-parameter limit.
Held-out routing, expert ablation, and an equal-total-parameter dense
comparison must then demonstrate meaningfully separate expertise.

## How the components fit together

```text
define the claim and count the deployed model
                     |
                     v
define terminal competence and its support abilities
                     |
                     v
build nonleaking semantic tasks and a trustworthy evaluator
                     |
                     v
admit data and establish feasible dense backbones
                     |
                     v
compare several specialization and compression operators
                     |
                     v
use matched controls to identify the cause of any gain
                     |
                     v
confirm on fresh seeds, a second backbone, and sealed tasks
                     |
                     v
export the exact artifact and measure its real footprint
```

This is a dependency chain, not a menu. Better statistics cannot repair a
leaked benchmark, and an excellent sandbox cannot make an incorrect verifier
scientifically meaningful. Likewise, a smaller file is not useful compression
until the runtime can load it and the target score survives.

## Scientific-design components

| Component | Why it matters | If it is missing or fails |
|---|---|---|
| **Claim boundary** | Fixes the only two success conditions: better terminal performance at fixed deployed size, or a better performance/footprint frontier. It keeps ability suppression, safety changes, and larger-model gains outside the claim. | A positive metric can be advertised as efficiency even though neither useful performance nor deployment cost improved. |
| **Dense model and footprint accounting** | Counts every physical parameter and deployed byte, including embeddings, output weights, tied storage, quantization scales, codebooks, and padding. It separates parameter count, artifact bytes, precision, memory, and latency. | A nominally sparse, quantized, or expert model may be described as smaller when the shipped system is not. |
| **Target definition** | Defines terminal skill as Bash/Unix-centered static program synthesis plus bounded terminal interaction, including Python when a task permits it, regex/text processing, structured formats, English comprehension, reasoning, and numeracy. | The method can improve a narrow command benchmark while damaging abilities that real terminal work needs. |
| **Capability-support audit** | Measures which non-target abilities help, hurt, or do not affect terminal performance. It replaces guesses about “irrelevant” languages or knowledge with transfer and add-back evidence. | There is no defensible basis for selecting an ability to sacrifice, and collateral damage can be mislabeled as recycling. |
| **Backbone feasibility gate** | Requires the starting dense model to be above floor, below target ceiling, and competent enough on candidate abilities for their loss to be measurable. | Floor and ceiling effects make a gain, null, or forgetting result uninterpretable. |
| **Two experimental lanes** | Keeps fixed-size specialization separate from compression. The former holds architecture and bytes fixed; the latter may change width, depth, vocabulary, factorization, or precision. | A quantized byte reduction may be mislabeled as fewer parameters, or a larger specialist may be mislabeled as fixed-size improvement. |
| **Operator funnel** | Compares dense tuning, replay, distillation, structured removal, reset/regrow at several granularities, vocabulary changes, factorization, and task-aware quantization before choosing a mechanism. | The study may assume SwiGLU channels are the answer merely because they are convenient to edit. |
| **Matched baselines** | Compares each proposed method with ordinary dense SFT, extra-compute SFT, layer-matched random removal/reset, no-reset sparse tuning, task-agnostic compression, uniform quantization, and native smaller models where applicable. | A gain caused by extra data, compute, generic plasticity, or ordinary compression can be given an unjustified mechanism label. |
| **Capability add-back tests** | Adds each declined audited capability back under the same total replay budget and asks whether its behavior returns and whether the target/footprint tradeoff changes. | Correlated ability loss is only collateral degradation; it is not evidence of recycled capacity. |
| **Protected-support evaluation** | Tracks the prerequisites needed for terminal work while applying the formal non-inferiority gates to static and bounded-terminal target performance. | A narrow static score may rise while the broader terminal capability becomes less useful. |

## Measurement components

| Component | Why it matters | If it is missing or fails |
|---|---|---|
| **Generator-backed semantic benchmark** | Builds distinct operator/dependency graphs, filesystem schemas, utility compositions, and output contracts instead of relying on paraphrased templates. | Memorized wording or template repetition can look like program-synthesis competence. |
| **Lifecycle splits and sealing** | Separates training, operator selection, method development, shadow checkpoint selection, and one-time final evaluation. | Feedback from the final test leaks into the method, turning confirmatory evidence into development evidence. |
| **Multiple hostile fixtures per task** | Executes one generated program against spaces, Unicode, dashes, globs, empty inputs, symlinks, duplicate records, permissions, and ordering variation. A task passes only if every fixture passes. | Plausible but brittle shell text receives credit despite failing ordinary adversarial filesystem cases. |
| **Frozen response parser and decoding** | Determines in advance how one model response becomes exactly one candidate and fixes generation limits, extraction, rerun, and failure policies. | Score changes can come from evaluator tuning rather than a better model. |
| **Runtime closure** | Pins Bash, utilities, loaders, libraries, locale, timezone, shell options, and other dynamically consumed runtime data. | Results can depend on mutable host state or differ across machines for reasons unrelated to the model. |
| **Rootless sandbox and trusted supervisor** | Prevents network and host access, enforces CPU/memory/PID/output/time limits, kills descendants, and establishes workspace quiescence before verification. | Untrusted programs may escape, survive timeouts, interfere with other runs, or mutate state while being scored. |
| **Independent oracle and property verifier** | Derives expected semantics independently and checks the complete final state rather than matching a reference string. | A shared implementation bug or a superficial output match can award credit to an incorrect program. |
| **Mutation and human audits** | Deliberately corrupt outputs and inspect whether prompts, fixtures, and verifiers agree. Independent constructions catch code bugs; human review catches specification mistakes. | Passing happy-path tests does not establish that the checker rejects realistic wrong answers or measures the intended task. |
| **Failure taxonomy** | Separates extraction, truncation, syntax, disallowed-tool, timeout, resource, infrastructure, and functional failures. | An evaluator problem and a model failure are both reduced to an ambiguous zero. |

## Training and comparison components

| Component | Why it matters | If it is missing or fails |
|---|---|---|
| **Corpus admission and decontamination** | Records row-level license, correctness, ambiguity, source, executable validity, and overlap with evaluation tasks. Raw content hashes establish identity but not eligibility. | Leakage, invalid commands, or unusable licenses can invalidate an otherwise strong training result. |
| **Target/protected replay design** | Holds total tokens fixed while comparing broad retention with minimal target-support replay. This tests whether dropping replayed abilities creates a real tradeoff. | An apparent recycling gain may simply come from receiving more target data. |
| **Token, optimizer, and FLOP ledger** | Counts real non-padding and supervised tokens, optimizer updates, learning rates, selection probes, calibration, teacher generation, and measured compute. | One arm may win because it had more learning opportunity or hidden selection cost. |
| **Optional verified teacher data** | Uses a larger teacher only to produce sequences that pass training fixtures, and gives identical accepted teacher data to comparable arms. A teacher-free arm remains required. | Student gains can be confused with privileged data or teacher quality rather than the proposed model intervention. |
| **Equal-token and equal-compute views** | Reports both practical target-token efficiency and a total-compute comparison that includes method-selection overhead. | A method may look superior only because the accounting boundary excludes its expensive search or calibration. |

## Confirmation and evidence components

| Component | Why it matters | If it is missing or fails |
|---|---|---|
| **Fresh training seeds** | Repeats promoted configurations with new randomness and paired data order after screening choices are frozen. | A lucky initialization or data order can be mistaken for a robust effect. |
| **Runner-up dense backbone** | Repeats the direct comparison on a second eligible non-MoE architecture. | The result remains a checkpoint-specific observation rather than evidence about a method. |
| **Independent static and bounded-terminal evaluation** | Tests the primary static-synthesis endpoint and whether the result transfers to a short interactive terminal loop. External benchmarks count only after handoff, leakage, verifier, and isolation audits. | The result can overfit one custom evaluator or fail to transfer to actual terminal behavior. |
| **Paired statistics and preregistered acceptance gates** | Fixes primary contrasts, bootstrap units, randomization tests, multiplicity correction, effect-size thresholds, and non-inferiority margins before sealed results are opened. | A favorable point estimate or selectively chosen metric can be promoted after the fact. |
| **Immutable manifests and evidence binding** | Links exact models, data, code, tasks, fixtures, seeds, masks, checkpoints, outputs, and analyses by content identity, reopening inputs at every boundary. | The reported result may not be reconstructable from the artifacts that supposedly produced it. |
| **Exact export proof** | Shows that selected structural or numerical changes are present in the shipped artifact and that untouched values remain what the method claims. | Training-time intentions may not match the model actually evaluated or distributed. |
| **Portable hardware protocol** | Measures load time, peak memory, latency, and throughput for the exact exported artifact under a controlled runtime, with non-GPU follow-up where supported. | Nominal parameter, sparsity, or byte savings may deliver no deployable benefit. |

## Why the order matters

The setup is intentionally front-loaded with benchmark and evidence work.
Training before those identities and boundaries are fixed can produce an
expensive but scientifically unusable checkpoint.

1. Define success and exact model accounting first.
2. Build and audit the semantic benchmark and execution boundary.
3. Freeze evaluation identities, then decontaminate and admit training data.
4. Establish model feasibility and capability transfer before selecting any
   ability for sacrifice.
5. Screen multiple operator families under matched budgets.
6. Freeze promoted methods and analysis before fresh-seed confirmation.
7. Open sealed suites once.
8. Measure the exact exported artifact on hardware.

This order also makes null results informative. If no above-floor ability is
negatively transferring, the capacity-competition premise is unsupported. If
random reset matches selected reset, generic plasticity is the explanation. If
uniform quantization matches ability-aware quantization, compression may still
work, but the ability-aware allocation has not earned credit.

## Current state of the setup

The current repository is building the **measurement and evidence foundation**,
not reporting a successful specialization or compression experiment.

- The scientific claim boundary, dense/non-MoE accounting rules, two result
  lanes, operator funnel, controls, and acceptance policy are specified.
- The public method-development allocation is locked at 25 semantic families
  and 500 tasks. Fourteen families/280 tasks currently have concrete oracles
  and 1,400 authenticated fixture bundles across five additive tranches.
- These development assets are public, unsealed, unscored, and
  nonauthorizing. The coverage lock is an allocation commitment, not proof of
  implementation, independent human review, candidate execution, or model
  quality.
- The remaining 11 families/220 tasks, beginning with
  `bounded-retry-state-machine`, still need implementation and review.
- General untrusted-candidate execution, independent human benchmark audit,
  sealed suites, claim-eligible corpus admission, backbone qualification,
  operator training, fresh-seed confirmation, and final hardware results are
  not yet complete.

The live and more granular status is always [IMPLEMENTATION.md](IMPLEMENTATION.md).
The current public allocation and its exact content identity are in
[configs/executable-method-development-coverage-v1.json](configs/executable-method-development-coverage-v1.json).

## Where the detailed answers live

- [PLAN.md](PLAN.md): authoritative scientific protocol and success thresholds.
- [EXPERIMENT_LOGIC.md](EXPERIMENT_LOGIC.md): dependency graph, claim ladder,
  and interpretation rules.
- [EXPERIMENT_COMPONENTS.md](EXPERIMENT_COMPONENTS.md): detailed conceptual
  guide to individual components.
- [EXPERIMENT_INFRASTRUCTURE.md](EXPERIMENT_INFRASTRUCTURE.md): trust boundaries,
  runtime isolation, artifact contracts, and evidence plumbing.
- [EXPERIMENT_EVIDENCE_CHAIN.md](EXPERIMENT_EVIDENCE_CHAIN.md): how component
  outputs compose into claim-eligible evidence.
- [RESEARCH_READINESS.md](RESEARCH_READINESS.md): compact build-state versus
  evidence-state assessment.
- [IMPLEMENTATION.md](IMPLEMENTATION.md): mutable implementation ledger and
  critical path.
