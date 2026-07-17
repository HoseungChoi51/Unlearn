# Why each experiment component matters

This document is a high-level guide to the experimental setup. It is organized
by the kind of evidence each component contributes, rather than by source-code
module or implementation milestone.

The authoritative protocol and numerical thresholds are in
[PLAN.md](PLAN.md). Current build status is in
[IMPLEMENTATION.md](IMPLEMENTATION.md), and the status of each component as
research evidence is summarized in [RESEARCH_READINESS.md](RESEARCH_READINESS.md).

The central question is:

> Can a dense, non-MoE language model below one billion physical parameters do
> Unix-terminal work better at the same deployed size, or preserve enough
> terminal performance in a smaller deployment to improve the
> performance/footprint frontier?

Forgetting is not the objective. A lost ability is relevant only if it causes
or enables a better target/footprint tradeoff. Likewise, safer behavior with
unchanged terminal performance and unchanged deployment size is outside this
study's success criteria.

There is no model-quality result yet. The current repository mainly builds the
measurement and evidence system needed to make a later result trustworthy.

## Four kinds of importance

The components are important in different ways:

1. **Claim-defining components** determine what question is being answered.
   If one is missing, the experiment may be internally correct but answer the
   wrong question.
2. **Validity-critical components** determine whether a score measures real
   terminal competence. If one fails, the score itself is not trustworthy.
3. **Interpretation-critical components** distinguish useful capacity
   specialization from extra training, random plasticity, generic
   compression, or collateral damage.
4. **Translation and reproducibility components** determine whether the
   reported model is a real deployable improvement and whether another
   researcher can reconstruct the evidence.

Teacher-assisted arms are part of the main comparison, and a teacher-free
ablation is required to quantify dependence on privileged data generation.
Only the expert appendix is trigger-conditional.

## End-to-end map

```text
WHAT COUNTS AS SUCCESS?
claim boundary + exact model/footprint accounting
                         |
                         v
WHAT MUST THE MODEL STILL DO?
terminal target + prerequisite/support definition
                         |
                         v
DOES THE SCORE MEAN WHAT WE THINK?
semantic tasks + sealed splits + isolated execution + verifier audits
                         |
                         v
ARE THE ARMS ACTUALLY COMPARABLE?
backbone gate + admitted data + token/FLOP ledger + matched baselines
                         |
                         v
WHAT CAUSED THE RESULT?
operator funnel + capability audit + restoration/add-back interventions
                         |
                         v
DOES THE EFFECT SURVIVE?
fresh seeds + paired statistics + second backbone + independent benchmarks
                         |
                         v
IS THE SHIPPED ARTIFACT REALLY BETTER?
exact export + byte/parameter accounting + hardware measurements + provenance
```

The order matters. Statistics cannot repair a leaked benchmark, and an exact
model hash cannot make an incorrect verifier scientifically meaningful.

## 1. Claim-defining components

| Component | Why it is important | What is invalid without it |
|---|---|---|
| Fixed-size and compression lanes | Separates better performance at identical deployed size from preserving performance in a smaller or lower-cost artifact | Quantization, pruning, or a larger specialist can be described with the wrong kind of efficiency claim |
| Dense sub-1B boundary | Counts every physical network parameter, including embeddings, output weights, and shared parameter storage | “Small” can refer to an incomplete or nominal parameter count rather than the deployed model |
| Physical deployment accounting | Reports parameters, artifact bytes, precision, memory, latency, and throughput separately | Zero weights, low average bits, or a smaller file can be mistaken for a real runtime benefit |
| Terminal target definition | Defines success as executable Unix-terminal behavior rather than Bash-like text | Surface syntax or a narrow command benchmark can replace actual task completion |
| Target-support definition | Protects English comprehension, reasoning, numeracy, task-relevant Python scripting, regex, structured data, and Unix concepts when they support terminal work | The intervention can improve a narrow score by deleting prerequisites needed in realistic use |

### Why there are two result lanes

Fixed-size specialization and compression answer different questions.

- In the **fixed-size lane**, architecture, physical parameters, serialized
  precision, and deployed weight bytes are held fixed. A gain measures better
  use of the same deployment budget.
- In the **compression lane**, the artifact may change, but it must move the
  measured terminal-performance frontier. Structural compression may reduce
  physical parameters; quantization may reduce bytes and memory without
  reducing parameter count.

Keeping the lanes separate prevents one convenient metric from hiding a worse
tradeoff elsewhere.

### Why the target has a support set

“Irrelevant ability” cannot be decided from a label. Knowledge learned from
another programming language, natural language, mathematics, or structured
data may support shell planning. The setup therefore protects known terminal
prerequisites and audits other capabilities empirically.

This is also why forgetting a programming language is only a possible
intervention, not the research direction. If no above-floor capability can be
removed beneficially, that is evidence against the capacity-competition
premise.

## 2. Validity-critical components

| Component | Why it is important | What is invalid without it |
|---|---|---|
| Generator-backed semantic benchmark | Creates distinct program graphs, filesystem states, utility compositions, and output contracts | Prompt-template recall can be mistaken for program synthesis |
| Bounded interactive suite | Tests short action/observation loops as required external-validity and non-inferiority evidence alongside primary static pass@1 | A static-only gain can be mistaken for broader terminal competence |
| Multiple hostile fixtures | Requires one candidate to survive spaces, Unicode, dashes, globs, empty inputs, links, permissions, duplicates, and ordering changes | Brittle but plausible shell text receives credit |
| Lifecycle splits and sealing | Separates training, operator selection, checkpoint selection, and one-time final testing | The final suite becomes development data |
| Leakage analysis | Measures prompt, syntax-tree, command-graph, and execution-trace similarity across lifecycle boundaries | Near-duplicate semantics can cross splits despite different wording |
| Frozen response parser and decoding | Turns one response into one candidate under fixed extraction, truncation, and rerun rules | Evaluator tuning can move pass@1 without a model improvement |
| Runtime closure | Pins the shell, tools, libraries, locale, timezone, options, and other consumed runtime data | Scores can depend on mutable host behavior |
| Rootless sandbox | Restricts network, mounts, privileges, and host access | Executing synthesized programs is unsafe and fixtures are not isolated |
| Trusted supervisor | Enforces time, CPU, memory, PID, and output bounds and establishes descendant quiescence | Timed-out or background processes can keep changing state during scoring |
| Independently implemented reference checker and property verifier | Checks the required semantic result and complete relevant filesystem state through an implementation independent of the benchmark generator | String similarity or a shared implementation mistake can award false passes |
| Mutation and human audits | Tests whether realistic wrong states are rejected and whether prompts mean what their verifiers implement | Unit-test consistency can hide checker blind spots or specification drift |
| Failure taxonomy | Separates extraction, syntax, policy, timeout, resource, infrastructure, and functional failures | Model errors and evaluator failures collapse into the same zero |

### Why benchmark work comes before model training

The primary endpoint is deterministic static functional pass@1, while the
bounded interactive suite supplies required external-validity and
non-inferiority evidence. Both evaluators are part of the scientific
instrument. If their semantics, isolation, or lifecycle are still changing,
model scores cannot be compared cleanly across time.

The public development families in this repository are therefore engineering
assets, not a result. Their generators, fixture bundles, oracles, mutation
tests, and immutable identities establish reusable measurement machinery.
They remain nonauthorizing until the general candidate boundary, independent
review, sealed suites, and campaign admission gates are complete.

### Why the oracle and sandbox are separate

These components resolve different uncertainties:

- The **sandbox** controls what an untrusted program can reach.
- Runtime closure controls **which semantics** its tools have.
- The **supervisor** controls how long it can act and whether it has stopped.
- The **oracle and verifier** decide whether its final state is correct.

Passing one does not imply the others. A safely contained program can still be
scored by a wrong checker, and a correct checker does not make arbitrary code
safe to execute.

## 3. Interpretation-critical components

| Component | Why it is important | What can still be claimed without it |
|---|---|---|
| Backbone feasibility gate | Ensures the starting model is above target floor, below target ceiling, and above floor on auditable non-target abilities | At most an uninterpretable pilot affected by floor or ceiling effects |
| Training-source admission | Requires row-level provenance, license eligibility, command correctness, ambiguity handling, balance, and decontamination | Reproducible engineering on raw data, not a claim-eligible training run |
| Target/protected replay design | Holds target exposure and total replay constant while changing what is retained | A data-mixture result, not evidence of capacity reallocation |
| Token, update, and FLOP ledger | Counts real supervised/non-padding tokens, optimizer updates, selection probes, calibration, teacher work, and conversion cost | An unequal-budget comparison |
| Operator funnel | Compares dense tuning, pruning, width/depth changes, vocabulary changes, factorization, quantization, distillation, and reset/regrow | A result for a chosen operator, not evidence that it is the best among the preregistered candidates and doses |
| Matched baselines | Tests ordinary SFT, extra-compute SFT, random intervention, no-reset tuning, task-agnostic compression, uniform quantization, and native smaller models | An empirical gain with a weaker causal label |
| Capability-support audit | Measures positive, neutral, and negative transfer rather than assuming which skills are dispensable | Specialization or compression without a sacrifice claim |
| Restoration and add-back tests | Ask whether the lost ability or removed structure mediates the improved tradeoff | Correlated collateral degradation, not demonstrated recycling |
| Protected-capability evaluation | Applies non-inferiority checks to abilities required by broader terminal use | A narrow benchmark gain only |

### Why the operator funnel is broad

SwiGLU channels are attractive because a matched gate row, up row, and down
column form a clean replaceable unit. That makes channel reset/regrow easy to
test causally, but convenience is not evidence that channels are the best use
of the capacity budget.

The funnel therefore also considers:

- ordinary dense post-training and replay changes;
- residual branches, attention-head groups, FFN blocks, and exportable hidden
  dimensions;
- layer, width, and vocabulary reduction;
- low-rank factorization and smaller dense students; and
- task-aware mixed-precision quantization.

If uniform quantization wins, the result is useful compression without
capability-aware allocation. If dense SFT wins, the right conclusion is that
structural intervention was unnecessary. If minimal-support dense SFT matches
the structured method, replay specialization rather than the structure
explains the gain.

### Why causal controls matter

A positive target delta alone does not reveal its cause. The required controls
form a ladder of stronger interpretations:

| Observation | Defensible interpretation |
|---|---|
| Extra-compute dense SFT matches the method | More optimization explains the gain |
| Minimal-support dense SFT matches the structured method | Replay specialization explains the gain |
| Random reset matches selected reset | Generic plasticity or regularization |
| No-reset sparse tuning matches reset/regrow | Parameter-efficient specialization |
| Uniform quantization matches target-aware quantization | Generic compression |
| Target improves without selective ability loss | Specialization, not sacrifice |
| Ability falls but add-back does not change the target tradeoff | Collateral degradation |
| Ability restoration reverses part of the target gain at matched budget | Evidence consistent with capability-mediated reallocation |

The experiment should report the weakest interpretation that survives these
controls.

## 4. Translation and reproducibility components

| Component | Why it is important | What is invalid without it |
|---|---|---|
| Fresh confirmation seeds | Tests whether a screened result survives new training randomness and data order | The effect may be a lucky screening run |
| Paired statistics and frozen acceptance gates | Quantifies uncertainty and fixes effect-size and non-inferiority rules before sealed results are known | A favorable point estimate or selected metric can become the conclusion |
| Runner-up dense backbone | Tests whether the result transfers beyond the selected checkpoint/backbone | The method remains checkpoint-specific |
| Independent benchmarks | Tests whether the result transfers beyond the custom suite after handoff and leakage audits | The result remains benchmark-specific |
| Exact export reconciliation | Proves that the shipped tensors, structure, precision, and archived/replaced units match the declared intervention | Training intent may differ from the artifact actually evaluated |
| Portable hardware protocol | Measures memory, loading, latency, and throughput for the exact export | Nominal byte or parameter savings may have no deployment benefit |
| Immutable manifests and registries | Bind models, data, tasks, fixtures, code, seeds, masks, checkpoints, outputs, and analyses by content identity | The evidence cannot be reconstructed or substitutions cannot be detected |

### Why deployment measurements are part of the experiment

Compression is not established by a pruning percentage or an average bit
count alone. The exact exported artifact must load in a real runtime, preserve
the target result, reduce the claimed resource, and be measured under the same
engine and workload as its baseline.

This is especially important below one billion parameters, where launch
overhead, tokenization, kernel support, and memory bandwidth may dominate.
RTX 5090 measurements are useful controlled evidence, but portable claims
need additional supported hardware strata.

### Why content hashes are necessary but insufficient

Hashes establish artifact identity. They do not establish that:

- a commitment was made before results were seen;
- data was licensed, correct, or uncontaminated;
- a runtime actually used the named artifact;
- a verifier measured the intended behavior; or
- a human independently reviewed the task.

The evidence chain therefore combines immutable identities with lifecycle
rules, reopening at trust boundaries, external commitments, and independent
review.

## 5. Teacher control and conditional expert extension

### Offline teacher

A larger dense teacher may generate fixture-verified training sequences in
the main fixed-size screening comparison, but comparable student arms must
receive the same accepted teacher corpus. A teacher-free ablation measures how
much the result depends on privileged data generation. Teacher assistance is
therefore a controlled comparison, not a post-success trigger.

### Sub-1B expert appendix

MoE is excluded from the main campaign. It is considered only if dense
experiments first reveal at least two reproducible capability clusters and the
complete routed network—including every expert and all shared weights—remains
below one billion physical parameters.

Even then, architecture alone does not prove separate expertise. Held-out
routing, expert-specific ablation, and an equal-total-parameter dense baseline
must show meaningful specialization. If the trigger does not fire, no MoE
implementation is needed.

## Minimum complete evidence chain

A model result becomes claim-eligible only when all of the following connect:

1. A frozen claim lane and exact model/footprint definition.
2. An eligible dense backbone with target headroom.
3. Admitted, decontaminated training data and a bound token/compute ledger.
4. Frozen static and bounded-interactive tasks, parser, decoding, runtime, and
   verifier identities.
5. A matched operator comparison with direct baselines.
6. Protected-capability results and any claimed capability add-back evidence.
7. Fresh-seed confirmation with the preregistered paired analysis.
8. One-time sealed evaluation and audited independent benchmarks.
9. Exact export reconciliation and, for compression, real footprint/hardware
   improvement.
10. An immutable chain linking every input, decision, output, and analysis.

Removing an item does not always erase all value. It limits the conclusion.
For example, a method can be an interesting engineering canary before sealed
evaluation, and a compressed file can be a storage result before portable
latency evidence. The documentation should state that narrower result rather
than promoting it to the full claim.

## Current emphasis

The repository is presently strengthening the validity-critical foundation:
semantic benchmark families, separately structured derivations, mutation
rejection, workspace verification, runtime boundaries, and immutable coverage
evidence. An independently implemented reference checker and stratified human
review remain open gates. This work is intentionally ahead of large
model-training campaigns because it defines the instrument that will score
them.

The remaining documentation, registries, and hash locks are necessary to
finish that instrument, but they are not model-quality evidence by themselves.
The next scientific transition occurs when the executable measurement boundary
is complete and independently reviewed, followed by claim-eligible data
admission and the three-backbone feasibility pilot. Only then can the operator
funnel produce a meaningful model comparison.

For exact, changing completion counts and open gates, use
[IMPLEMENTATION.md](IMPLEMENTATION.md) and
[RESEARCH_READINESS.md](RESEARCH_READINESS.md) rather than this conceptual
guide.
