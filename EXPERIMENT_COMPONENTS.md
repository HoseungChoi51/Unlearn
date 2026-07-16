# Experiment components and why they matter

This is the short conceptual guide to the experiment. It explains the role of
each major component, the failure it is meant to prevent, and how the pieces
fit together. For the full research design, see [PLAN.md](PLAN.md). For the
implementation-level security and evidence boundaries, see
[EXPERIMENT_INFRASTRUCTURE.md](EXPERIMENT_INFRASTRUCTURE.md). Current completion
status is tracked in [IMPLEMENTATION.md](IMPLEMENTATION.md). The longer
research-reader explanation of how these components compose is
[EXPERIMENT_EVIDENCE_CHAIN.md](EXPERIMENT_EVIDENCE_CHAIN.md).

The experiment is not primarily about making a model forget. It asks whether a
dense model below one billion physical parameters can perform Unix-terminal
work better at the same deployed size, or retain useful performance at a
smaller deployed size. An ability is worth sacrificing only when its measured
loss helps one of those two outcomes.

There is no model-quality result yet. The repository currently contains
research contracts, benchmark and runtime foundations, and engineering
canaries. Those pieces make a future score interpretable; they are not
themselves evidence that a specialization or compression method works.

## The experiment at a glance

```text
scientific question and claim boundary
                  |
                  v
       model, data, and task identities
                  |
                  v
      feasibility and capability audits
                  |
                  v
       matched intervention screening
                  |
                  v
         fresh-seed confirmation
                  |
                  v
 isolated execution on sealed fixtures
                  |
                  v
 paired statistics and claim acceptance
                  |
                  v
   reproducible model + evidence bundle
```

Every arrow is important. A strong trainer cannot compensate for a leaked
benchmark, an unsafe evaluator, an incorrectly counted model, or a comparison
that gave one arm more data or compute.

## Component map

| Component | Why it is important | What can go wrong without it |
|---|---|---|
| Claim boundary | Defines success as better terminal performance at fixed size, or a better performance/footprint frontier | Ability suppression or a safety change could be mislabeled as capacity improvement |
| Dense sub-1B accounting | Establishes the actual object being compared, including embeddings, output weights, quantization metadata, and shared storage | A nominally small or sparse model may not be physically smaller or deployable |
| Backbone feasibility pilot | Chooses a model with enough target headroom and enough non-target competence to support a meaningful tradeoff test | Floor and ceiling effects can make every intervention look ineffective or artificially strong |
| Terminal target definition | Protects Bash, Unix tools, Python scripting, structured data, English comprehension, and reasoning that terminal work genuinely needs | The study may remove a capability that looks unrelated by name but is necessary in practice |
| Capability-support audit | Empirically identifies abilities that help, hurt, or do not affect the target | A programming language or knowledge family could be declared dispensable from intuition alone |
| Training-data admission | Separates reproducible raw imports from rows that are licensed, correct, unambiguous, decontaminated, and suitable for training | Data leakage, invalid commands, or duplicated templates may create a false gain |
| Token schedule and optimizer ledger | Makes target exposure, replay, updates, and measured compute comparable across arms | One method may win because it received more supervised tokens, fewer padding tokens, or more optimization |
| Generator-backed benchmark | Measures many distinct semantic programs and edge cases rather than surface similarity | Template repetition or text overlap can be mistaken for terminal competence |
| Lifecycle splits and sealing | Separates method invention, checkpoint selection, and final testing | Repeated inspection of the test set turns it into development data |
| Parser and deterministic decoding | Fixes how model text becomes one candidate program | Parser tweaks, reruns, or changing token limits can move the score without changing the model |
| Runtime closure and sandbox | Gives every candidate the same tools while isolating the host, network, and other fixtures | A candidate may depend on mutable host state, escape its workspace, or interfere with another task |
| Trusted supervisor | Enforces wall, CPU, memory, process, and output limits and reaps descendants before verification | Background processes and forked children can survive timeouts or mutate state during scoring |
| Independent oracle and property verifier | Decides whether the final output and filesystem state satisfy the task semantics | A shared bug or string-matching shortcut can award credit to an incorrect program |
| Mutation and human verifier audits | Tests the checker by deliberately corrupting outputs and reviewing whether tasks mean what their prompts say | Passing unit examples may hide blind spots or a mismatch between prose and implementation |
| Operator funnel | Compares dense tuning, distillation, structural pruning, vocabulary changes, quantization, and reset/regrow units before promoting a method | The study may assume SwiGLU channels are optimal merely because they are convenient to manipulate |
| Baselines and causal interventions | Distinguish selective reallocation from extra compute, generic plasticity, ordinary sparse tuning, or random regularization | A gain may be attributed to forgetting when a random reset or extra training would do the same thing |
| Protected-capability and add-back tests | Check that retained terminal support survives and whether a sacrificed ability actually mediates the gain | Correlated degradation may be reported as useful capacity recycling without causal evidence |
| Fresh seeds and runner-up replication | Tests whether the result survives stochastic training and a second eligible architecture | One lucky seed or one model-specific quirk may be mistaken for a general method |
| Paired statistics and acceptance gates | Fix the primary contrast, uncertainty calculation, non-inferiority limits, and success thresholds | Selective metrics or noisy point estimates may be promoted after the result is known |
| Immutable manifests and registries | Bind model, data, code, masks, seeds, fixtures, outputs, and results into one auditable chain | A digest copied into a report may refer to an artifact that was never reopened or actually used |
| Portable hardware protocol | Measures memory, latency, and throughput on a reproducible deployment path | Parameter or byte savings may fail to produce a real deployment benefit |

## 1. Scientific contract and measurement lanes

The claim boundary is the top-level control. It keeps two questions separate:

1. **Fixed-size specialization:** does terminal accuracy improve while the
   architecture, physical parameter count, precision, and deployed weight
   bytes stay fixed?
2. **Compression:** can a smaller or lower-precision artifact preserve enough
   terminal performance to improve the Pareto frontier?

This separation prevents a quantized model from being described as having
fewer parameters and prevents an accuracy gain obtained through a larger
deployment from being called fixed-size improvement. Physical parameters,
serialized bytes, precision, peak memory, latency, and functional accuracy are
reported separately.

The primary study excludes MoE models. A sub-1B expert appendix is allowed only
after dense-model evidence reveals reproducible capability clusters, and only
if all shared weights, experts, router, embeddings, and output weights fit
below the same physical-parameter limit. Separate expertise then has to be
demonstrated by routing and ablation, not inferred from architecture labels.

## 2. Models and capability support

The backbone pilot is a feasibility gate, not a model leaderboard. The chosen
base model must have room to improve on executable terminal tasks, must already
solve enough tasks to avoid a behavioral floor, and must show several
non-target abilities above floor. Otherwise the experiment cannot distinguish
successful specialization from an incapable starting point.

The capability audit protects the *support set* for terminal work. Python,
regex, structured formats, English instructions, numeracy, and concepts learned
through other programming languages may all support Bash performance. No named
ability is presumed irrelevant. Cross-fitted removal, add-back, and transfer
tests determine whether a family is helpful, neutral, or negatively
transferring.

This also clarifies the role of forgetting. A declining capability is evidence
only when it began above floor, the target or footprint improved, matched
nonselected abilities did not decline in the same way, and restoration or
add-back changes the target effect in the predicted direction.

## 3. Data and training controls

Raw-data reproducibility and training eligibility are different properties.
Content hashes prove which bytes were imported; they do not prove row-level
license compatibility, command correctness, absence of evaluation leakage, or
fitness for the target. The admission stage therefore records a decision and a
reason for each row, verifies executable examples where applicable, resolves
ambiguous prompts, balances tool coverage, and decontaminates against every
known evaluation suite.

The token schedule fixes exactly how much target data and protected replay each
arm sees. Packing and accumulation are accounted using real non-padding and
supervised tokens, while the optimizer ledger records updates and measured
FLOPs. These controls make equal-target-token and equal-total-compute
comparisons possible.

A larger dense teacher is optional and offline. It can improve the shared
training corpus only by supplying fixture-verified sequences, and comparable
arms receive the same accepted teacher examples. A teacher-free ablation is
needed so a successful student method is not confused with a stronger data
generator.

## 4. Benchmark semantics and lifecycle

The benchmark is generator-backed because terminal correctness is semantic.
One natural-language specification defines an operator graph, filesystem
schema, utility composition, and output contract. One generated program is
then tested against multiple hidden fixtures. The task passes only if every
fixture passes.

Splits are separated by normalized program structure and state schema, not
just prompt text. This reduces the chance that a differently worded copy of a
training program appears in the test set. Edge profiles exercise spaces,
Unicode, leading dashes, glob characters, empty inputs, duplicates, symlinks,
permissions, and unstable ordering because those cases reveal much of the
difference between plausible shell text and robust shell programs.

Lifecycle roles prevent feedback leakage:

- training tasks may update model weights;
- operator-selection and method-development tasks may shape the method;
- shadow validation selects a checkpoint;
- sealed in-distribution and compositional-OOD suites are opened once after
  method and analysis lock.

The static suite supplies the primary functional endpoint. A bounded
interactive suite checks whether a gain transfers to a short terminal loop.
External benchmarks are diagnostics until their candidate handoff, identity,
decontamination, verifier, and isolation properties meet the same standard.

## 5. From model text to trusted outcome

Several components sit between model output and a score:

```text
model response
    -> frozen parser
    -> syntax and allowed-tool checks
    -> authenticated invocation
    -> isolated runtime and trusted supervisor
    -> quiescent workspace
    -> independent semantic verification
    -> bound task outcome
```

The parser and deterministic decoding contract prevent extraction policy,
reruns, or generation limits from becoming hidden tuning parameters. Failure
classes remain separate so infrastructure errors, syntax failures, timeouts,
output overflow, and functional failures are not collapsed into an ambiguous
zero.

The sandbox is necessary because the object being evaluated is untrusted
executable code. Runtime closure pins the actual Bash binary, utilities,
loader, libraries, locale, and dynamically opened resources. The rootless
namespace removes network and host access, and the supervisor enforces resource
ceilings, captures output, terminates the full process tree, and keeps the
workspace still while it is inspected.

The oracle and verifier are deliberately distinct. The oracle derives the
expected semantics; the verifier checks the complete final state and forbids
unexpected mutations. Independent reference logic, mutation tests, and human
review address different checker failures and are all needed before sealing.

## 6. Methods, controls, and causal interpretation

The operator funnel exists because the best specialization unit is an
empirical question. Fixed-size candidates include ordinary dense SFT,
distillation, replay changes, low-rank or sparse tuning, and reset/regrow at
several structural granularities. Compression candidates include structured
width or layer removal, vocabulary trimming, factorization, distillation, and
task-aware quantization. SwiGLU channels are one candidate unit, not the
premise of the study.

Matched baselines explain a positive result. Examples include extra-step dense
SFT, random reset/regrow, target-only plasticity selection, no-reset sparse
tuning, task-agnostic pruning, uniform quantization, and a natively smaller
dense model. All receive the same data, channel or parameter budget where
applicable, optimization schedule, and tuning opportunity.

Mechanism tests then ask what caused the gain. Restoring removed structure,
disabling replacement structure, capability add-back, and attribution tests
should move terminal and sacrificed-capability performance in the predicted
directions. If random or no-reset controls match the method, the correct result
is generic plasticity or parameter-efficient specialization—not capacity
recycling.

## 7. Confirmation, statistics, and deployment evidence

Screening narrows the operator set; it does not establish the result. Promoted
arms run on fresh seeds, and the core comparison repeats on a second eligible
dense backbone. Tasks and training seeds are paired so differences are measured
on the same sources of variation. Bootstrap intervals, randomization tests,
multiple-comparison correction, and protected-capability non-inferiority bounds
are fixed before the sealed suite is opened.

The final acceptance gate combines all important dimensions: target gain,
footprint or fixed-size status, protected capability, causal controls, fresh
seeds, equal-compute comparison, and independent evaluation. A statistically
positive Bash score alone is insufficient.

For compression, the exported artifact must also produce a real deployment
benefit. The portable hardware protocol measures peak memory, latency,
throughput, and runtime compatibility from the exact hashed artifact. This
guards against nominal sparsity or metadata savings that the inference runtime
cannot exploit.

## 8. Provenance and present readiness

Prospective run specifications, campaign registries, evaluation contracts,
per-task outcomes, model inspections, training ledgers, and immutable manifests
form the evidence chain. Each stage must reopen and validate its inputs rather
than trust copied identifiers. External publication or timestamping is still
needed for preregistration because hashes alone do not prove when a commitment
was made.

Engineering canaries are intentionally outside the claim path. They test one
mechanism—such as model loading, token scheduling, descriptor transport,
namespace construction, or PID1 cleanup—under a small closed contract. Passing
a canary reduces implementation risk but does not authorize arbitrary model
candidates, research training, scoring, model selection, or a scientific
claim.

The near-term dependency order is:

1. finish and independently review the executable development benchmark;
2. finish the candidate runtime, supervisor, tool-policy, and workspace-
   quiescence boundary;
3. finish the leakage controls, human audit, and sealed suites, then freeze
   their identities without exposing them to training or method development;
4. admit a claim-eligible corpus decontaminated against those frozen suite
   identities;
5. extend the implemented narrow completed floating-dense source/export
   reopening into exporter-specific selected-unit/value proof, fresh or
   attested runtime evidence, and factorized/quantized/hybrid accounting, then
   complete production-training infrastructure;
6. run the feasibility gates and freeze the backbone;
7. run matched baselines, operator screening, and fresh-seed confirmation;
8. open the sealed evaluation only after the method and analysis are locked.

This order is conservative because later stages depend on earlier identities.
Running a large training campaign before the evaluator and data admission are
closed would create expensive outputs that cannot support the intended claim.
