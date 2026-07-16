# Experiment logic: how the setup earns a claim

This document is the high-level decision map for the experiment. It explains
why the major components are needed, how they depend on one another, and how
to interpret both positive and negative results. The authoritative protocol
and acceptance thresholds remain in [PLAN.md](PLAN.md). Detailed engineering
boundaries are in [EXPERIMENT_INFRASTRUCTURE.md](EXPERIMENT_INFRASTRUCTURE.md),
and current completion status is in [IMPLEMENTATION.md](IMPLEMENTATION.md).

The project asks whether a dense language model with fewer than one billion
physical parameters can do Unix-terminal work better at the same deployed
size, or retain useful terminal performance in a smaller deployment. Turning
off an ability is not success by itself. It matters only when the change
improves target performance or the performance/footprint frontier.

There is no model-quality result yet. Current canaries and contracts establish
parts of the evidence chain; they do not authorize research scoring, model
selection, or a scientific claim.

## What counts as success

The experiment keeps two result lanes separate.

1. **Fixed-size specialization** improves executable terminal performance
   while architecture, physical parameter count, precision, and deployed
   weight bytes remain fixed.
2. **Compression** preserves enough terminal performance that a genuinely
   smaller or cheaper artifact improves the measured Pareto frontier.

Quantization may succeed in the compression lane by reducing bytes, memory, or
latency. It does not reduce the number of physical parameters. Nominal
sparsity is not compression unless the exported representation and runtime
realize a deployment benefit.

The primary study is non-MoE. A sub-1B expert appendix is permitted only if the
dense study first finds reproducible capability clusters and the complete
network—including shared weights, every expert, router, embeddings, and output
head—remains below one billion physical parameters. Routing and ablation must
then demonstrate meaningfully separate expertise.

## Dependency graph

```text
scientific claim contract
    |
    +-- model and deployment accounting
    |
    +-- benchmark semantics --+--> frozen suite identities
    |                         +--> corpus decontamination and admission
    |
    +-- execution boundary ---+--> quiescent workspace
                              +--> independent verification
                                      |
                                      v
                         feasibility and capability audit
                                      |
                                      v
                         matched operator screening
                                      |
                                      v
                         fresh-seed confirmation
                                      |
                                      v
                         sealed evaluation, once
                                      |
                                      v
                         exact export and hardware evidence
                                      |
                                      v
                              final claim gate
```

This order is part of the method. Benchmark identities must exist before
decontamination can be meaningful. The execution boundary and verifier must be
trusted before a functional score is credible. Screening must finish before
fresh confirmation seeds are chosen, and the sealed suite is opened only
after method and analysis lock. Deployment measurements must use the exact
export whose model result is being claimed.

## Why each component matters

| Component | Question it answers | Why it is important | What its failure means |
|---|---|---|---|
| Claim contract | What outcome is the study allowed to call success? | Prevents forgetting, safety suppression, or a larger model from being mislabeled as capacity efficiency | The result is out of scope even if one metric improves |
| Dense-model accounting | What network and physical storage are actually deployed? | Counts embeddings, output weights, tied storage, quantization metadata, and all optional expert machinery | Size or compression comparisons are not valid |
| Target and support definition | Which abilities are part of competent terminal use? | Protects English, reasoning, Python, Unix concepts, regex, structured formats, and other transferable knowledge | An apparent specialization may simply damage prerequisites |
| Backbone feasibility gate | Is the starting model above floor and below target ceiling? | Creates room to observe both improvement and meaningful capability loss | A null is uninterpretable because of floor or ceiling effects |
| Capability audit | Which abilities help, hurt, or do not affect terminal work? | Replaces intuition about “irrelevant” skills with cross-fitted transfer and add-back evidence | No ability can be defensibly selected for sacrifice |
| Semantic benchmark generator | Does the suite measure distinct programs rather than prompt templates? | Separates executable competence from memorized wording and exercises compositional structure | Target gains may be leakage or template matching |
| Lifecycle splits and sealing | Which data may shape the method, checkpoint, or final claim? | Prevents method-development feedback from entering the final test | The affected suite becomes development data |
| Corpus admission and decontamination | Are training rows lawful, correct, relevant, and separated from evaluation? | Raw hashes alone do not establish license compatibility, command validity, or absence of leakage | Training evidence remains engineering-only |
| Parser and decoding contract | How does one model response become one candidate program? | Prevents extraction changes, retries, and token limits from becoming hidden tuning knobs | Score changes cannot be attributed to the model |
| Runtime closure | Which exact shell, utilities, loaders, libraries, locale, and runtime data are available? | Makes every candidate face the same tool semantics and removes mutable host dependencies | Execution is not reproducible or sufficiently isolated |
| Namespace and supervisor | Can untrusted code outlive limits, access the host, or mutate state during verification? | Enforces network, process, CPU, memory, output, privilege, and quiescence boundaries | Functional evaluation is unsafe or causally ambiguous |
| Oracle and property verifier | Did the program produce the required state for the right reason? | Checks semantic output and the complete filesystem policy rather than reference-string similarity | A pass has no reliable meaning |
| Mutation and human audits | Would the verifier reject plausible wrong states, and does the task mean what its prompt says? | Independent constructions catch shared implementation bugs; human review catches specification drift | The suite is not ready to seal |
| Token, update, and FLOP ledger | Did compared arms receive equivalent learning opportunity? | Separates method effects from extra target data, padding, updates, or selection compute | A winner may only have received more optimization |
| Operator funnel | Which unit—dense weights, channels, blocks, layers, vocabulary, or precision—best improves the objective? | Keeps SwiGLU recycling as one candidate rather than an assumed answer | The study may optimize a convenient but inferior mechanism |
| Matched baselines | Does selection beat random reset, target-only plasticity, no-reset tuning, ordinary SFT, and uniform compression? | Identifies the simplest explanation for a gain | The stronger causal label must be rejected |
| Restoration and add-back tests | Did the sacrificed ability or recycled structure mediate the target gain? | Distinguishes useful reallocation from correlated damage | Report specialization or collateral loss, not recycling |
| Fresh seeds and second backbone | Does the effect survive stochasticity and model choice? | Guards against lucky runs and architecture-specific quirks | The result remains preliminary or model-specific |
| Paired statistics and acceptance gate | Is the gain larger than uncertainty while protected skills remain non-inferior? | Fixes contrasts, multiplicity correction, and success thresholds before seeing sealed results | A favorable point estimate is insufficient |
| Export and hardware protocol | Does the exact artifact deliver real memory, latency, or throughput benefit? | Connects structural or byte claims to an executable deployment | Compression is storage-only, unsupported, or unrealized |
| Immutable evidence chain | Can every result be traced to exact model, data, code, fixture, seed, mask, and output identities? | Makes reconstruction and independent audit possible | The provenance chain, not necessarily the result, has failed |

No row can compensate for a failed dependency below it. For example, stronger
statistics cannot repair a leaky benchmark, and a hardened sandbox cannot make
an incorrect verifier scientifically valid.

## Claim ladder

Infrastructure evidence is intentionally promoted in stages:

1. **Unit or mechanism test:** one parser, hash, verifier rule, or lifecycle
   property behaves as specified.
2. **Engineering canary:** several components interoperate under a closed,
   explicitly non-claiming contract.
3. **Fixed reviewed-development case:** one exact reviewed program, fixture,
   runtime, supervisor, and verifier can be connected without accepting an
   arbitrary candidate.
4. **Arbitrary development candidate:** the complete boundary accepts
   untrusted model output, but still cannot score or select research models.
5. **Screening evidence:** admitted data and development tasks compare methods
   under matched budgets.
6. **Confirmatory evidence:** promoted arms run with fresh seeds and the frozen
   analysis.
7. **Sealed benchmark evidence:** the final suites are opened once and produce
   claim-eligible outcomes.
8. **Deployment evidence:** exact exports demonstrate the claimed footprint or
   hardware advantage and pass the final policy gate.

The current reviewed-Bash work targets level 3. Its public execution entry
point accepts only an optional nonce and no caller-selected program, command,
fixture, runtime, or verifier; it permanently denies candidate, scoring,
model-selection, and claim authority. Even a successful
fixed-case run would not establish arbitrary-candidate safety, complete Bash
runtime-data or `dlopen` closure, external trust in the binaries, a general
seccomp/tool policy, or research readiness.

## How controls determine the conclusion

| Observation | Defensible interpretation |
|---|---|
| Random reset/regrow matches targeted selection | Generic plasticity or regularization |
| Target-only prospective selection matches capability-guided selection | Sparse target specialization, not selective forgetting |
| No-reset sparse tuning matches reset/regrow | Parameter-efficient specialization without demonstrated recycling |
| Minimal-support dense SFT matches the structured method | Replay or data mixture explains the gain |
| Uniform quantization matches target-aware quantization | Compression works, but ability-aware allocation adds no evidence |
| Target improves without selective ability loss | Targeted specialization or reinitialization, not sacrifice-based reallocation |
| Ability declines but restoration/add-back does not affect the target | Correlated collateral damage, not causal mediation |
| No above-floor, negatively transferring ability is found | Valuable null against the capacity-competition premise |
| Fresh confirmation fails | Screening result or seed-specific effect |
| Second dense backbone fails | Architecture-specific result |
| Smaller artifact has no memory or runtime advantage | Nominal or storage-only compression |
| External benchmark cannot meet handoff and verifier gates | Diagnostic evidence only |

These are not fallback stories chosen after the fact. They are the purpose of
the controls: each one determines which explanation survives.

## Current critical path

The immediate path to a model experiment is:

1. finish and independently audit concrete executable tasks, fixtures,
   verifiers, mutation coverage, and suite identities;
2. close runtime-data, external-trust, exact-tool, general candidate, and
   independent sandbox-review gates;
3. admit and decontaminate training data against the frozen evaluation
   identities;
4. run backbone floor/ceiling and capability-transfer gates;
5. screen dense specialization and compression operators under equal token and
   compute budgets;
6. promote only preregistered winners to fresh confirmation and the one-time
   sealed evaluation.

See [IMPLEMENTATION.md](IMPLEMENTATION.md) for the mutable task ledger. Public
and content-frozen development data must never be relabeled as sealed evidence.
A content hash establishes identity, not when a commitment was made; external
publication or trusted timestamping is still required for preregistration.

## Document ownership

- [PLAN.md](PLAN.md) owns the scientific protocol, thresholds, and scope.
- This document owns the high-level dependency and decision logic.
- [EXPERIMENT_COMPONENTS.md](EXPERIMENT_COMPONENTS.md) is the component-level
  conceptual guide.
- [RESEARCH_READINESS.md](RESEARCH_READINESS.md) is the compact two-axis
  build-state and evidence-state synthesis.
- [EXPERIMENT_INFRASTRUCTURE.md](EXPERIMENT_INFRASTRUCTURE.md) owns detailed
  trust boundaries and evidence plumbing.
- [IMPLEMENTATION.md](IMPLEMENTATION.md) is the mutable completion ledger.
- [README.md](README.md) is the repository orientation and command index.
