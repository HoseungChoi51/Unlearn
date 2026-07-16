# Experiment evidence chain: why every component matters

This document is a research reader's guide to the evidence the experiment must
produce. It explains the question answered by each infrastructure component,
why that evidence cannot be replaced by a nearby component, and what is
implemented versus still planned.

The authoritative scientific protocol and thresholds are in
[PLAN.md](PLAN.md). [EXPERIMENT_COMPONENTS.md](EXPERIMENT_COMPONENTS.md)
provides a shorter conceptual inventory,
[EXPERIMENT_LOGIC.md](EXPERIMENT_LOGIC.md) explains the dependency and
interpretation logic, and
[EXPERIMENT_INFRASTRUCTURE.md](EXPERIMENT_INFRASTRUCTURE.md) documents the
technical trust boundaries. Current status belongs in
[RESEARCH_READINESS.md](RESEARCH_READINESS.md) and
[IMPLEMENTATION.md](IMPLEMENTATION.md); those files should be consulted before
treating any statement below as a completion claim.

There is no model-quality result yet. The present repository contains bounded
contracts, validators, public development fixtures, and engineering canaries.
They reduce ambiguity in a future experiment, but they do not show that any
specialization or compression method improves terminal performance.

## The two estimands

The study has two primary lanes and should not collapse them into one ratio.

1. **Fixed-size specialization** estimates the paired change in executable
   terminal performance when architecture, physical parameter count,
   serialized precision, weight bytes, and deployed model shape are held
   fixed.
2. **Compression** estimates the terminal-performance Pareto frontier over
   physical parameters, weight bytes, peak memory, latency, and throughput.
   Quantization can improve byte, memory, or runtime dimensions without
   reducing the number of physical parameters.

The primary accuracy endpoint is macro-averaged deterministic functional
pass@1 at the semantic-task level. One generated program must pass every
hidden fixture for its task. Fixture successes are therefore not independent
observations and cannot be counted as separate tasks.

Capability loss is not a third success metric. It is relevant only to a causal
interpretation: an above-floor ability may be called sacrificed or dispensable
only if its decline helps terminal performance or footprint and restoration or
add-back changes that tradeoff in the predicted direction. A safety or
alignment change with unchanged size and target performance is outside the
estimand.

The primary campaign is restricted to dense, non-MoE models with fewer than
one billion total physical parameters, including embeddings and output
weights. The triggered expert appendix remains out of scope unless the dense
study first finds reproducible capability clusters and the complete routed
network, including every expert and router, still fits below the same limit.
Any triggered expert result must additionally demonstrate meaningfully
separate expertise through routing and ablation rather than infer it from the
architecture label.

## Evidence map

| Component | Question it answers | Current evidence | What is still missing |
|---|---|---|---|
| Claim and estimand contract | What numerical change would count as success? | Protocol, run, evaluation, and acceptance contracts exist | No eligible campaign outcome |
| Model and scope gate | Is the compared object a supported dense sub-1B model with room to improve? | Exact static Qwen2/Qwen3/Llama qualification and engineering load/forward probes | Executable floor/ceiling and capability gates |
| Data admission and leakage | Did training use correct, licensed, nonambiguous, nonleaking examples? | Raw-source authentication, lexical filtering, and exact token scheduling | Bash parsing, execution verification, lineage, balancing, and full decontamination |
| Benchmark lifecycle | Are development, selection, and final testing genuinely separated? | Public development registries and prospective split contracts | Complete reviewed development suites and unopened sealed ID/OOD suites |
| Sandbox, supervisor, and verifier | Does a pass mean the candidate safely caused the required final state? | Fixture/oracle mutation tests and one fixed reviewed-program integration path | Independently trusted arbitrary-candidate boundary and production verifier audit |
| Identity and provenance | Can every number be traced to exact bytes and code? | Domain-separated hashes, manifests, registries, and bounded reopeners | End-to-end source reopening, external timestamping, and trust anchors |
| Intervention and export accounting | Did the planned operator refer to real model structure, and did the export realize it? | Prospective architecture-aware bounds; narrow fresh static source/export reconciliation with supported pruning-dimension checks | Exact selected-unit/value proof and broader exporter support |
| Runtime and hardware evidence | Does the exact artifact load, run, and deliver a deployment benefit? | Engineering runtime reports and passive reconciliation to fresh static identities | Fresh or attested runtime graph/value evidence and campaign hardware samples |
| Training and compute controls | Did arms receive equal target exposure and comparable optimization? | Deterministic schedules and an engineering dense-SFT canary | Production trainer and executed-FLOP provenance |
| Baselines and equal-compute controls | Is a gain more than ordinary SFT, extra compute, or generic plasticity? | Prospective arm and campaign contracts | Matched screening and confirmation runs |
| Evaluation and statistics | Is the effect functional, paired, uncertain, and multiplicity controlled? | Result schemas and confirmatory analysis validators | Trusted scored outcomes from frozen suites |
| Causal interventions | Did removed capability or recycled structure mediate the gain? | Preregistered interpretation rules | Swap, disable, restoration, add-back, and attribution results |
| Reproducible release | Can another group reconstruct the model and evidence chain? | Content-addressed engineering artifacts | Complete portable campaign bundle and independent replay |

## 1. Claim contracts prevent target drift

The claim contract fixes the target, footprint dimensions, primary endpoint,
protected-capability margins, and promotion thresholds before methods are
compared. This matters because many attractive but different outcomes can
otherwise be substituted after the fact: lower loss instead of executable
success, nominal sparsity instead of a smaller artifact, or ability suppression
instead of better terminal performance.

Run specifications separate prospective budgets from completed measurements.
Campaign registries bind arms, contrasts, seeds, and promotion relationships.
Evaluation specifications freeze parsing, decoding, task membership, failure
classification, reruns, and exclusions. Claim acceptance is deliberately the
last projection in the chain; it cannot repair missing evidence upstream.

**Implemented:** schemas and fail-closed validators for these prospective and
completed records.

**Planned:** actual research runs whose data, execution, export, hardware, and
evaluation sources are independently eligible for those validators.

## 2. The model and scope gate establishes the denominator

Performance per size is meaningless until model size is defined consistently.
The accounting must include embeddings, output weights, tied storage, buffers,
precision, tokenizer rows, and the complete exported bundle. Physical
parameters, nonzero values, serialized bytes, memory, and latency are distinct
quantities.

The backbone feasibility pilot then asks whether the model is scientifically
usable. A model at terminal floor cannot reveal which intervention helps, and
a model at ceiling leaves no headroom. The original model must also place
several audited non-target capabilities above floor before a later decline can
support a sacrifice claim. This is a feasibility decision, not a general model
leaderboard.

**Implemented:** exact static tensor inventories for supported floating-point
Qwen2, Qwen3, and Llama checkpoints; physical parameter, dtype, payload,
tokenizer-row, and operator-bound checks; local engineering load and finite
forward reports for the three shortlisted artifacts.

**Planned:** functional terminal scores, bounded-terminal development results,
non-target capability floors, and the preregistered primary/runner-up choice.
The present GPU probes establish fit and mechanics only.

## 3. Data admission is separate from raw-data reproducibility

A hash can prove which source bytes were imported, but not whether a row is
correct, licensed, safe for the target policy, or free of evaluation overlap.
The admitted training view must therefore record a reasoned decision for every
row and remain joinable to the immutable raw source.

Admission covers at least:

- row-level source and license lineage;
- Bash parsing and positive allowed-tool policy;
- execution or independent semantic verification where applicable;
- exact and near duplicate removal;
- repair or rejection of normalized prompts with incompatible completions;
- utility and semantic-family balance; and
- decontamination against every available evaluation identity.

Decontamination cannot stop at case-folded prompt matching. Terminal prompts
contain case-sensitive and byte-sensitive literals. The final audit must
report prompt, program AST, normalized command graph, and execution-trace
neighbors under versioned, literal-preserving policies. It must be rerun when
new evaluation suites are frozen.

**Implemented:** authenticated raw import, a conservative nonexecuting lexical
prefilter, normalized-prompt collision accounting, deterministic prerequisite
generation, and exact token/packing schedules.

**Planned:** claim-eligible row admission. The current lexical survivors and
generated support rows have not passed the required AST, execution, lineage,
human-review, or evaluation-overlap gates and cannot feed a research run.

## 4. Split lifecycle and leakage controls protect the endpoint

The benchmark roles answer different questions:

- training data may update weights;
- operator-selection and method-development data may shape the method;
- shadow validation may choose a checkpoint;
- sealed in-distribution and compositional-OOD suites estimate the locked
  method once.

Separation must occur by semantic operator/dependency graph, utility
composition, filesystem schema, solution family, and output contract—not just
by row identifier or wording. Otherwise a paraphrased program template can
cross the split while appearing textually different.

**Implemented:** lifecycle fields and fail-closed routing contracts, 200
integrated public method-development tasks with 1,000 concrete fixtures, and
40 additional staged tasks with 200 fixtures. These are public, unsealed, and
nonauthorizing. Large generated records are semantic scaffolding, not complete
executable or sealed suites.

**Planned:** independent review and integration of the staged families, the
remaining method-development coverage, real operator-selection and shadow
identities, complete leakage reports, and genuinely unopened sealed ID/OOD
suites. A file labeled `sealed_ood` in public scaffolding is not sealed evidence.

## 5. Execution isolation and semantic verification define a pass

The evaluated object is untrusted executable code. A trustworthy score needs
the complete path:

```text
model text
  -> frozen parser and deterministic decoder
  -> authenticated candidate/task/fixture binding
  -> rootless isolated runtime with pinned tools
  -> bounded supervisor and complete descendant cleanup
  -> quiescent final workspace
  -> independent property/state verifier
  -> content-bound outcome record
```

The sandbox prevents host, network, container-socket, and cross-fixture access.
The runtime closure pins Bash, utilities, the loader, libraries, locale, and
other resources that influence behavior. The supervisor bounds wall time,
cumulative CPU, memory, PIDs, files, and output; kills and reaps descendants;
and establishes quiescence before the trusted controller reads results.

The verifier must check semantic output and complete filesystem/process state,
not reference-string similarity. A separate oracle construction, mutation
testing, and stratified human review catch different classes of verifier bug.

**Implemented:** a frozen response parser and diagnostic host syntax check;
ten integrated fixture/oracle families with independent constructions and
mutation coverage; namespace, runtime-snapshot, and native PID1 canaries; and
one exact reviewed Bash case connected through the local boundary.

**Planned:** a production, independently reviewed arbitrary-candidate service
with a trusted Bash runtime closure, exact-tool enforcement, tmpfs/workspace
ceilings, cumulative resource enforcement, quiescence, and scored result
binding. The fixed reviewed case has no caller-selected candidate API and is
not evidence that arbitrary synthesized Bash is safe or correct.

## 6. Identity and provenance connect observations to bytes

The evidence chain uses different identities for different objects. A weight
set, complete bundle, tokenizer sources, tensor layout, task registry, fixture
set, runtime report, and completed run should not share an ambiguous digest.
Domain separation and canonical ordering prevent two meanings from being
silently substituted behind the same field.

A copied digest is still only a statement. High-value binders reopen source
artifacts, recompute their identities, and compare independently derived
accounting. Reports also retain code, dependency, policy, seed, and hardware
identities so later discrepancies are diagnosable.

Hashes do not provide authenticity, external trust, confidentiality, or proof
of preregistration time. External publication or trusted timestamping is
needed for a temporal commitment, and locally hashed runtime binaries still
need an independent trust basis.

**Implemented:** immutable registries and manifests, defensive JSON and file
readers, domain-separated model/data/task identities, source-code hashes, and
fresh static reinspection for the narrow completed-model companion path.

**Planned:** complete source reopening through training, evaluation, hardware,
statistics, and final claim acceptance, plus external commitments and
independent reproduction.

## 7. Intervention and export accounting test whether capacity moved

The operator funnel is broad because SwiGLU channels are only one plausible
unit. Candidate interventions include dense tuning, replay changes,
distillation, reset/regrow, residual or attention groups, FFN blocks, hidden
width, layers, vocabulary, factorization, structured pruning, and
task-conditioned precision.

Prospective validation asks whether selected indices exist, GQA groups remain
representable, factorization ranks are legal, and declared quantization bytes
are arithmetically possible. Completed validation asks a different question:
whether the exported artifact actually has the promised structure, precision,
parameter count, tokenizer mapping, and bytes.

These checks must not be conflated. Matching a planned parameter count does
not by itself prove that the requested heads, channels, layers, or vocabulary
rows were the units exported. Likewise, a reset/regrow artifact with unchanged
shape does not prove which weights were reset or trained.

**Implemented:** prospective source-checkpoint binding for supported Qwen2,
Qwen3, and Llama structure; representable pruning counts; exact factorization
tuples; quantization payload lower bounds; and a narrow companion that freshly
reinspects floating-point dense source/export artifacts and reconciles broad
identity and accounting fields to a completed record. Supported layer,
uniform FFN-width, and uniform all-layer Qwen3 complete-GQA-group head-width
pruning must also produce the corresponding architecture-dimension change;
completed embedding-token pruning fails closed until its derived mapping can
be replayed.

**Planned:** exporter-specific topology and mapping diffs that prove the
selected operator payload was realized, exact hidden/residual and broader head
compression contracts, factorized and quantized artifact formats, hybrid
exports, quantizer metadata/padding, and correctness tests on every completed
artifact.

## 8. Runtime evidence is not one thing

Three evidence levels should remain separate:

1. **Static artifact evidence** reconstructs stored tensors, shapes, dtype,
   payload bytes, tokenizer rows, and bundle identity without loading the
   model.
2. **Model-runtime evidence** loads an artifact, accounts physical storage,
   and performs a bounded finite forward pass.
3. **Deployment evidence** measures repeated load, prefill, decode, memory,
   latency, throughput, and compatibility on a fixed backend and hardware
   stratum.

The current completed-model companion freshly reopens source and export bytes
for static inspection. It passively validates previously saved runtime reports
and reconciles their reported aggregate storage, architecture class, and
logits vocabulary to the fresh static identities. It does not rerun the model,
authenticate those saved observations, verify the exact loaded
name/shape/alias/value graph, prove that training consumed the source bytes,
measure declared nonzero parameters, validate a claimed runtime compatibility
list, or prove that selected operator units were realized.

**Implemented:** bounded engineering load/forward reports, semantic validation
of their passive record shape, and the narrow static-to-saved-runtime
reconciliation above.

**Planned:** freshly rerun or independently attested runtime graph/value
evidence for completed artifacts and the portable hardware protocol in
[HARDWARE.md](HARDWARE.md). No terminal-quality or deployment-speed result is
currently available.

## 9. Training controls make arm differences interpretable

Equal examples are not necessarily equal exposure. Packing, truncation,
padding, supervised-token masks, gradient accumulation, checkpoint selection,
and selection probes can all change the effective budget. Each arm therefore
needs exact target, support, and teacher-visible token ledgers; optimizer-step
and learning-rate traces; and measured selection, optimization, compression,
and total FLOPs.

Protected replay is part of the estimand. All-retain and minimal-support arms
must keep total replay and target exposure fixed so that removing one family
does not secretly grant extra target data. Verified teacher sequences must be
identical across comparable dense and intervention arms, with a teacher-free
ablation.

**Implemented:** deterministic corpus transforms, visible/supervised-token
accounting, packing and update schedules, campaign budget contracts, and one
real-text dense-SFT engineering canary.

**Planned:** a production trainer whose executed operator trace derives FLOPs,
research-eligible admitted data, all required operators, controlled
checkpoint selection, and campaign outputs. The canary demonstrates plumbing
and fit, not a terminal result or a completed research arm.

## 10. Baselines and equal compute decide the explanation

A positive intervention is informative only relative to alternatives that can
explain the same gain. Required controls include ordinary dense SFT, extra-step
dense SFT matched to total compute, random reset/regrow, target-only
prospective selection, no-reset sparse tuning, task-agnostic pruning, uniform
quantization, a natively smaller dense model, and relevant established
target-aware methods.

Comparisons should be reported both at equal target tokens and equal total
FLOPs, including selection and look-ahead computation. Each arm receives the
same tuning budget, data order where applicable, decoding policy, tasks, and
fixtures. Screening chooses candidates; fresh confirmation estimates their
effect. Reusing screening seeds as confirmation would bias the estimate.

**Implemented:** prospective arm schemas, cohort/contrast rules, seed
registries, and compute ceilings.

**Planned:** the matched screening matrix, fresh confirmation seeds, runner-up
backbone replication, and measured FLOP reconciliation. Until those runs
exist, no mechanism is a winner.

## 11. Evaluation and statistics turn executions into an estimate

The evaluation layer freezes how one response becomes one candidate and how
one candidate becomes one outcome. Extraction failure, truncation, syntax
failure, tool-policy failure, timeout, runtime failure, output overflow, and
functional failure remain separate. Infrastructure reruns follow a fixed
policy and cannot become extra attempts after a functional failure.

The primary contrast pairs arm, training seed, task, and fixture policy.
Uncertainty is resampled at the semantic-task level with training-seed
variation represented explicitly. Randomization tests, multiplicity
correction, and simultaneous non-inferiority intervals protect against
promoting one favorable endpoint while retained capabilities decline.

Sealed suites are opened only after methods, checkpoints, parser, decoding,
exclusions, reruns, and analysis are locked. External benchmarks remain
diagnostic until candidate handoff, task identity, verifier, decontamination,
and isolation are independently adequate.

**Implemented:** prospective evaluation contracts, content-bound task-result
and collection validators, paired confirmatory statistics, and fail-closed
claim-policy projections.

**Planned:** deterministic production decoding, trusted candidate execution,
complete result collections, the one-time sealed evaluation, independent
benchmark ports, and actual statistical contrasts. Existing public
development assets and BashBench release diagnostics cannot supply the primary
endpoint.

## 12. Causal tests constrain the story told about a gain

Target accuracy and an ability decline can be correlated without one causing
the other. The study therefore requires interventions on the proposed
mechanism:

- restore archived structure or weights;
- disable newly learned replacement structure;
- add back replay for a declined capability while keeping total tokens fixed;
- compare selected and matched nonselected capabilities;
- measure attribution and gradient/activation movement into the proposed
  capacity; and
- test bounded relearning without treating recoverability as certified data
  deletion.

The controls determine the language of the result. If random reset matches the
method, the finding is generic plasticity. If target-only selection matches,
it is sparse target specialization. If no-reset tuning matches, reset-based
forgetting is unnecessary. If the ability loss does not mediate the target
effect, it is collateral degradation rather than recycled capacity.

**Implemented:** preregistered intervention fields, capability-audit contracts,
and interpretation rules.

**Planned:** all behavioral causal interventions, capability add-backs,
selectivity comparisons, attribution measurements, and fresh-seed estimates.

## 13. Reproducibility is an end-to-end property

Reproducibility requires more than publishing a model file. A release must
bind model revisions and bytes, tokenizer and prompt serialization, raw and
admitted data, transformation code, task and fixture identities, container
image and utilities, training order, masks, optimizer states, checkpoints,
generated responses, per-task outcomes, statistical inputs, export format,
and raw hardware samples.

Portable records should be defensive and content-addressed, but an independent
reproduction still needs the referenced bytes and enough code to rebuild each
derived artifact. Host-specific measurements must retain their backend,
driver, compiler, power, and hardware stratum; an RTX 5090 latency result does
not automatically transfer to a CPU, iGPU, or shared-memory laptop.

**Implemented:** many component-level manifests, stable identities, source
hashes, deterministic transforms, and bounded validators.

**Planned:** the complete campaign bundle, external prospective commitments,
independent artifact reopening, second-backbone replication, independent
terminal benchmark evidence, and later portable hardware replay.

## Readiness gates before a scientific result

The campaign should advance only when each preceding gate has evidence:

1. The estimand, thresholds, and lifecycle roles are frozen.
2. Dense source models and deployment accounting are exact and externally
   pinned.
3. Development tasks, fixtures, oracles, mutation tests, and human review are
   complete enough for the backbone feasibility gate.
4. The arbitrary-candidate sandbox and verifier are independently trusted on
   the target hardware.
5. Evaluation identities exist, and all training partitions are admitted and
   decontaminated against them.
6. The production trainer and executed-FLOP ledger pass bounded pilots.
7. Backbones pass floor/ceiling and capability-support requirements.
8. Matched operator screening promotes only preregistered arms.
9. Fresh seeds, causal tests, protected-capability intervals, and runner-up
   replication succeed.
10. Methods and analysis are locked before the single sealed opening.
11. Exact exported artifacts pass correctness and portable hardware checks.
12. The final claim binder reopens every required source rather than trusting
    copied projections.

Failure at a gate is scientifically informative. It may produce a principled
null, a diagnostic limitation, or a redesign decision. It does not authorize
skipping the gate or relabeling an engineering artifact as research evidence.

## Explicit non-claims at the current stage

The current workspace does not establish that:

- any shortlisted backbone is best or even behaviorally eligible;
- any training row is claim-admitted;
- public development fixtures are sealed, scored, or model-selection evidence;
- arbitrary synthesized Bash can be safely and correctly executed;
- the saved runtime reports are independently attested or freshly rerun by the
  completed-model companion;
- a completed export realizes the exact selected channels, heads, layers, or
  vocabulary mapping merely because its aggregate count matches;
- any specialization, pruning, factorization, vocabulary, quantization, or
  reset/regrow method improves terminal performance or footprint;
- any ability is irrelevant, dispensable, forgotten, or causally recycled;
- a smaller nominal model is faster or uses less memory on a real deployment;
- a diagnostic external benchmark independently confirms a result; or
- the expert appendix trigger has fired.

The strongest present statements are engineering statements about bounded
mechanisms: exact supported static model inspection, deterministic data and
token transformations, public fixture/oracle generation and mutation
behavior, fixed-case runtime integration, passive completed-model evidence
reconciliation, and statistical contract validation. Each remains narrower
than the scientific conclusion the full chain is designed to support.
