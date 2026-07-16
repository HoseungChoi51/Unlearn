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
| Benchmark lifecycle | Are development, selection, and final testing genuinely separated? | Public development registries, a locked 25-family allocation, and prospective split contracts | Complete reviewed development suites and unopened sealed ID/OOD identities |
| Data admission and leakage | Did training use correct, licensed, nonambiguous, nonleaking examples? | Raw-source authentication, lexical filtering, and exact token scheduling | Bash parsing, execution verification, lineage, balancing, and decontamination against those frozen suite identities |
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

Raw-source auditing and candidate curation may proceed early, but
**claim-eligible decontamination cannot finish until the evaluation suite
identities are frozen**. Suite identity therefore precedes final admission in
the evidence chain; admitting first and later checking against a moving target
would make the training denominator ambiguous.

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

**Implemented:** lifecycle fields and fail-closed routing contracts, plus 300
integrated public method-development tasks with 1,500 concrete fixtures across
six additive tranches. The third addition contributes 40 tasks/200 fixtures
from compound path queries and regex log aggregation. Its exact family-local
types preserve the first- and second-tranche identities, and its checked
hash-only report is
[`reports/executable-third-tranche/manifest.json`](reports/executable-third-tranche/manifest.json).
The added registry, cumulative suite, additive catalog, and canonical report
byte SHA-256 values are
`66a9ef43a6387f5f94f511aec3357f0e625427d161a0c6da0d9590a837761237`,
`3a578668805bbdfdfaf3400483640bb29504591604ed1c9c28cf8f9bb0362fb3`,
`01554367fd68c36b2f509b8b50b270b0aa7d5e6de3fa55db15a14cf4ec68c26b`,
and `58e7e299142bd2c9681f9940f8277489115fa76350ffa53fb984bed81ceac862`.
The fourth addition contributes 20 `reproducible-ustar-pack` tasks/100 fixtures.
Its checked hash-only report is
[reports/executable-fourth-tranche/manifest.json](reports/executable-fourth-tranche/manifest.json);
the task-set, added-registry, cumulative-suite, additive-catalog, and canonical
report-byte SHA-256 values are
`be044d13053e62e0a9f609e1654048de4c7b422e9bc93c659f0d265ddfd4e283`,
`3dc5512139361a275afaf0b57b94528961615f9b4eee22ee6c333cc7d8bf4ea5`,
`668ab9c942888d568c80aaa27bee340ad8a10faf3493a6983bf068d79b134651`,
`54ff2e17645edfc7887fc39b437340ffe8d736b83001d0265612271c2a3b1d46`,
and `a79ba062de86574e95ff60ff4fa8bc48b223c934b70d65ed832da5631359eebb`.

The fifth addition contributes 20 `pipefail-atomic-report` tasks/100 fixtures.
Its checked hash-only report is
[reports/executable-fifth-tranche/manifest.json](reports/executable-fifth-tranche/manifest.json);
the task-set, added-registry, cumulative-suite, additive-catalog, and canonical
56,246-byte report SHA-256 values are
`fc974695fe967094bcba6c6f8ff8c267c86f64215de78c43a8e693bed1252562`,
`d562d462814b7fc6413e0e085d16f66def28157c1a6361adf28cd3d42eb5f88c`,
`27ea8064a72453a4e7a4bc52b125a924139088cd1c20d417a867aa9ddda96e00`,
`cb24e42fc27500fa5076224dfc195a6fe2a4b08752724f09ff944961aa7221db`,
and `80959058c764da72437bfa1bd01a2eb1c747a221ec1c06f59278c02b80e0ef48`.

The sixth addition contributes 20 `bounded-retry-state-machine` tasks/100
fixtures. Its checked hash-only report is
[reports/executable-sixth-tranche/manifest.json](reports/executable-sixth-tranche/manifest.json);
the task-set, added-registry, cumulative-suite, additive-catalog, and canonical
report-byte SHA-256 values are
`112e9d079a1b21b2d371e61d48af2401649b23aeff11a45e4d2dcbe847e1541c`,
`14280b3cbc8a96c919a57a325b5795c381cba86b2a31934f7069821b7ff4e3c4`,
`db6d00278664f5a72834ebf0297411564da8b98a75d08eb2c2e9cf706dc985b1`,
`9042968ead33dd098870d21582bc3114706d3af3841bdb3ab7a0d40c5727d990`,
and `3661d9fe60d78de51bf518fff32282b437b770515c7bbb9a1263072dfb0d13ac`.

The full allocation lock contains 15 integrated families/300 tasks and 10
planned families/200 tasks. Its semantic coverage SHA-256 is
`732186b4ddec708f067127ab1b1b8caeb42d84316fcc13f3a748f7e018ae7c4b`,
and its canonical config-byte SHA-256 is
`b96f416ef118c013c7edc909131a452189022630601bcc7d312b9641adb1f5cf`.
The lock fixes scope only; it does not implement or seal its planned entries.
All current assets are public, unsealed, unscored, and nonauthorizing. The
third through sixth manifests and the allocation lock explicitly record
`independent_human_review_attested: false`; the additive families remain
outside the first-tranche-only V1 invocation protocol. Large generated records
are semantic scaffolding, not complete executable or sealed suites.

**Planned:** the remaining 200 method-development tasks, beginning with
`case-routed-batch-transform`, independent review of the complete development
inventory, real operator-selection and shadow
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
fifteen integrated fixture/oracle families with independent constructions and
mutation coverage; namespace, runtime-snapshot, and native PID1 canaries; and
one exact reviewed Bash case connected through the local boundary.

The fourth-family verifier observes final state only. It still requires a
trusted supervisor to establish quiescence and cannot attest transient
`chmod`, symlink-follow, or tool-invocation history; explicit directory-mode
and live effective-access failures are also outside its current fixtures.

The fifth-family trusted semantics consume complete logical streams, preserve
the ordered configured status vector, and select the exact success, failure,
rollback, or absent-output final state for each publication policy. Its
checked-in tests exercise both semantic constructions, catalog materialization,
randomized valid streams, and final-state mutations without executing a
candidate program. The verifier requires trusted quiescence and cannot attest
atomic-rename history, Bash `PIPESTATUS`, executed pipeline topology, tool
history, or global quiescence. Explicit
directory-permission and live effective-access failures are also outside its
fixtures.

The sixth-family ledger distinguishes success, transient failure, ordinary
failure, and terminal failure. Five behaviorally distinct retry policies apply
one-, two-, four-, or six-attempt limits per state visit, with budgets reset on
every visit; fixed and until-terminal policies retry transient and ordinary
failures, transient-only retries only transient failures, and terminal failure
always stops retrying. Separately structured trusted paths derive exact
attempt and terminal reports for linear, branching, bounded-cyclic, and
compensating models. The final-state verifier does not attest actual retry,
waiting, transition, compensation, tool-use, atomic-publication, transient-input,
global-quiescence, or candidate-exit history. Directory-permission and live
effective-access behavior also remain outside the fixtures.

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
5. Evaluation task and fixture identities are frozen while their sealed assets
   remain closed.
6. All training partitions are admitted and decontaminated against those
   already-frozen identities.
7. The production trainer and executed-FLOP ledger pass bounded pilots.
8. Backbones pass floor/ceiling and capability-support requirements.
9. Matched operator screening promotes only preregistered arms.
10. Fresh seeds, causal tests, protected-capability intervals, and runner-up
   replication succeed.
11. Methods and analysis are locked before the single sealed opening.
12. Exact exported artifacts pass correctness and portable hardware checks.
13. The final claim binder reopens every required source rather than trusting
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
