# Experiment setup component map

This document explains, at a high level, what each part of the experiment
contributes and why it is necessary. It is organized around the evidence
needed to answer the research question, rather than around source-code
modules.

The authoritative protocol and thresholds are in [PLAN.md](PLAN.md).
[IMPLEMENTATION.md](IMPLEMENTATION.md) tracks what has actually been built.
[EXPERIMENT_INFRASTRUCTURE.md](EXPERIMENT_INFRASTRUCTURE.md) describes the
technical trust boundaries in detail.

The research question is:

> Can a dense, non-MoE language model below one billion physical parameters
> perform Unix-terminal work better at the same deployed size, or preserve
> enough terminal performance in a smaller deployment to improve the
> performance/footprint frontier?

Forgetting is not the objective. An ability loss matters only when it enables
one of those two outcomes. Likewise, a safety or alignment change with
unchanged target performance and size is outside the claim.

There is no model-quality result yet. The current repository is building the
measurement, execution, and evidence system that will make such a result
interpretable.

## The setup in one picture

```text
                  WHAT COUNTS AS A WIN?
        claim boundary + model/footprint accounting
                              |
                              v
                   WHAT MUST BE PRESERVED?
           terminal target + capability-support audit
                              |
                              v
                    WHAT DOES THE MODEL SEE?
          admitted data + split lifecycle + token ledger
                              |
                              v
                    WHAT ARE WE COMPARING?
         operator funnel + baselines + matched compute
                              |
                              v
                    DID THE PROGRAM WORK?
        parser -> sandbox -> supervisor -> semantic verifier
                              |
                              v
                   IS THE EFFECT BELIEVABLE?
       causal tests + fresh seeds + statistics + replication
                              |
                              v
                   IS THE ARTIFACT ACTUALLY BETTER?
          exact export + hardware measures + provenance
```

Each layer closes a different uncertainty. No downstream component can repair
a failed upstream one: a confidence interval cannot rescue a leaked
benchmark, and a correct verifier cannot make unequal-compute training arms
comparable.

## Component summary

| Component | Its unique job | Why it is important |
|---|---|---|
| Claim boundary | Defines fixed-size specialization and compression as separate success lanes | Prevents ability suppression, nominal sparsity, or a larger model from being called capacity improvement |
| Model and footprint accounting | Counts the exact network and deployable artifact | Makes “same size” and “smaller” measurable rather than rhetorical |
| Target and support definition | Defines terminal competence and the abilities it may depend on | Prevents removal of Python, reasoning, structured-data, or language knowledge that terminal work actually uses |
| Backbone feasibility gate | Establishes headroom, target competence, and measurable non-target abilities | Avoids floor and ceiling effects that make interventions uninterpretable |
| Capability-support audit | Measures positive, neutral, and negative transfer instead of guessing what is irrelevant | Supplies defensible candidates for sacrifice and supports informative null results |
| Corpus admission | Decides which authenticated rows are legally and semantically fit for training | Blocks invalid commands, ambiguity, leakage, and lineage problems from driving a false gain |
| Split lifecycle and sealing | Separates training, method selection, checkpoint selection, and final testing | Keeps confirmatory evaluation from becoming development data |
| Semantic benchmark generator | Produces distinct executable problems and hostile fixtures | Measures program behavior rather than prompt similarity or template memorization |
| Response and decoding contract | Turns one model response into one candidate deterministically | Removes parser changes, retries, and generation settings as hidden tuning knobs |
| Runtime closure and sandbox | Gives candidates identical pinned tools while isolating the host | Makes execution reproducible and safe enough to interpret |
| Trusted supervisor | Enforces resource limits, kills descendants, and establishes quiescence | Prevents timeouts or background processes from changing state during verification |
| Independent oracle and verifier | Determines whether the required final state was produced | Makes a pass a semantic claim rather than a string-match result |
| Mutation and human audits | Test whether the benchmark rejects plausible errors and says what its authors intend | Finds checker blind spots and specification mistakes that ordinary unit tests miss |
| Operator funnel | Compares multiple specialization and compression mechanisms | Avoids assuming that SwiGLU channels, or any convenient unit, are optimal |
| Training and compute ledger | Equalizes target exposure and records every material selection/training cost | Separates method effects from extra data, updates, or compute |
| Matched baselines | Tests simpler explanations such as ordinary SFT, random reset, or uniform quantization | Determines which causal interpretation a gain has earned |
| Restoration and add-back tests | Ask whether removed ability or structure mediates the gain | Distinguishes capacity reallocation from correlated collateral damage |
| Protected evaluations | Check that useful terminal-support capabilities remain non-inferior | Stops a narrow benchmark gain from hiding a less useful terminal model |
| Confirmation and statistics | Quantify effect size and uncertainty on fresh seeds and paired tasks | Prevents lucky seeds and selected metrics from becoming the result |
| Exact export and hardware protocol | Measures the artifact that would actually be deployed | Verifies that paper compression becomes real byte, memory, latency, or throughput improvement |
| Immutable provenance | Binds inputs, code, tasks, models, outputs, and analyses by content | Makes the result reconstructable and exposes substitutions or missing evidence |

## 1. Scientific scope and accounting

### Claim boundary

The project has two estimands:

1. **Fixed-size specialization:** terminal performance changes while
   architecture, physical parameter count, serialized precision, and deployed
   weight bytes stay fixed.
2. **Compression:** terminal performance is evaluated jointly with physical
   parameters, artifact bytes, peak memory, latency, and throughput.

The distinction matters because a quantized artifact can use fewer bytes
without having fewer parameters, while a sparse tensor can have many zeros
without being smaller or faster in its actual runtime.

### Model boundary

The primary comparison is dense and non-MoE. Every embedding, output weight,
buffer, quantization scale, codebook, and shared storage object must be
accounted for. A possible expert appendix is deliberately gated: the complete
routed model must remain below one billion physical parameters, and routing
plus ablation must demonstrate genuinely different expertise.

This component establishes the denominator of “performance per capacity.”
Without it, the central comparison is undefined.

## 2. Target competence and capability support

### Terminal target

The target is executable Unix-terminal work, not Bash-token prediction alone.
It includes shell control flow and quoting, Unix utilities, filesystem and
process reasoning, regex and text processing, JSON/CSV/YAML handling, Python
when allowed, English instruction following, and basic reasoning and
numeracy.

This broad definition prevents specialization from deleting prerequisites
that a narrow benchmark fails to name.

### Backbone feasibility

Before comparing methods, a backbone must be:

- above the target floor;
- below the target ceiling;
- able to solve bounded terminal tasks; and
- above floor on several auditable non-target capabilities.

This gate creates observable room for both improvement and sacrifice. If the
model never possessed a capability, its later absence is not forgetting. If
the target is already saturated, a null intervention result says little.

### Capability-support audit

Candidate abilities are selected empirically. Cross-fitted transfer probes,
target gradients, removal or attenuation interventions, and capability
add-back determine whether an ability supports, competes with, or is neutral
to terminal performance.

This audit is central to the updated research direction: programming-language
forgetting is only one possible case. Any ability may be a candidate, but none
is declared irrelevant from its label alone. Finding no above-floor,
negatively transferring capability is a useful null result against the
capacity-competition premise.

## 3. Data and benchmark lifecycle

### Training-data admission

Downloaded bytes are raw evidence, not automatically valid training data.
Admission must establish row-level provenance and license status, command
correctness, target-tool compliance, ambiguity handling, duplicate control,
coverage balance, and contamination checks against every frozen evaluation
identity.

This separates reproducibility from suitability. A perfect source hash can
reproduce a contaminated or incorrect corpus exactly.

### Split lifecycle

Training, operator selection, method development, shadow validation, and
sealed ID/OOD testing have different permissions. Splits are separated by
program graph, utility composition, filesystem schema, solution family, and
output contract rather than by prompt wording alone.

The sealed suites are opened once after the method, checkpoint rule, parser,
and analysis are locked. This is what allows the final score to estimate
generalization rather than continued development.

### Generator-backed semantic tasks

Each specification represents an executable semantic problem. One generated
candidate must pass multiple hidden fixture states, including difficult
filenames, empty input, duplicates, links, permissions, and ordering changes.
A task passes only if all of its fixtures pass.

The generator provides controlled coverage and structural split identities.
The hostile fixtures expose shell programs that look plausible but fail under
normal filesystem edge cases.

## 4. Executable evaluation

### Response parser and deterministic decoding

The parser fixes how raw text or one optional code fence becomes exactly one
candidate. Generation limits, truncation handling, reruns, and failure
categories are frozen with it.

This matters because parser leniency or an extra attempt can raise pass@1
without any model change.

### Runtime closure, sandbox, and supervisor

Runtime closure pins Bash, utilities, libraries, locale, timezone, shell
options, and dynamically consumed data. The rootless sandbox removes network
and host access and supplies an isolated writable workspace. The trusted
supervisor enforces wall time, CPU, memory, process, and output limits, reaps
descendants, and establishes a stable workspace before verification.

These are distinct jobs. The sandbox controls what a program can reach;
runtime closure controls what semantics it sees; the supervisor controls how
long it can act and whether activity has really stopped.

### Oracle and property verifier

The oracle independently derives the expected semantics. The verifier checks
the complete relevant final state: output bytes, file types, modes, links,
absence requirements, and task-specific relations. It does not reward textual
similarity to a reference program.

Independent constructions, mutation testing, and stratified human review are
needed because a checker can be internally consistent and still implement the
wrong task. These components establish different facts:

- unit and differential tests establish implementation consistency;
- mutations establish sensitivity to plausible wrong states; and
- human review establishes agreement between prompt, task intent, and checker.

## 5. Intervention comparison

### Operator funnel

The experiment compares mechanisms before choosing one:

- ordinary dense post-training and replay changes;
- structured pruning at layer, head, hidden-width, block, or FFN-channel
  granularity;
- reset/regrow and sparse specialization;
- vocabulary trimming and factorization;
- task-aware quantization and mixed precision;
- distillation into a smaller dense model; and
- eligible hybrids with explicit accounting.

SwiGLU-channel recycling remains attractive because it permits a clean
matched-size swap, but it is a candidate rather than the premise. The funnel
asks which operator improves the actual objective under comparable budgets.

### Training ledger and matched controls

Every arm records supervised and non-padding tokens, replay composition,
optimizer steps, selection probes, calibration, and measured FLOPs. Results
are reported at both equal target-token and equal total-compute boundaries.

Matched baselines test whether the gain is explained by ordinary SFT,
extra-compute SFT, random intervention, target-only selection, no-reset sparse
tuning, uniform or task-agnostic compression, or a native smaller model. A
method name is not an explanation; the controls determine the explanation.

### Causal and protected-capability tests

Swap-back, re-zero, restoration, and capability add-back ask whether the
modified structure and the declined ability actually mediate the target gain.
Protected evaluations check terminal prerequisites and general language
quality under predeclared non-inferiority margins.

If an ability declines but restoring it does not affect the target tradeoff,
the defensible finding is collateral degradation—not recycled capacity.

## 6. Confirmation, deployment, and evidence

### Fresh confirmation and statistics

Screening nominates a configuration; it does not establish the result.
Promoted methods use fresh seeds, paired data order and tasks, a runner-up
dense backbone, independent benchmarks, semantic-task-level bootstrap
intervals, paired randomization tests, multiplicity correction, and
non-inferiority checks.

This component turns a development observation into an uncertainty-bounded
comparison. Failure to replicate narrows the claim instead of being averaged
away.

### Exact export and hardware measurement

The evaluated export must realize the selected structure, numerical format,
and unchanged-value claims. Compression results then measure weight bytes,
loadability, peak memory, latency, and throughput using that exact artifact.

This closes the gap between an algorithmic compression proxy and a useful
deployment. A smaller checkpoint with no supported runtime or no memory
benefit is not the same result as a smaller working model.

### Immutable provenance

Manifests and registries bind model revisions, tokenizer, source data,
admission decisions, task and fixture identities, code, environment, seeds,
operator selections, ledgers, checkpoints, outputs, analyses, and exports.
Consumers reopen and validate source artifacts rather than trusting copied
digests.

Provenance does not make a weak result strong, but it makes every strength and
limitation inspectable. External publication or trusted timestamping is still
required to establish when a prospective commitment existed.

## What the current infrastructure means

The repository currently contains scientific contracts, model/data/training
canaries, public method-development task families, semantic verifiers,
content-addressed registries, and bounded execution foundations. The committed
coverage v5 allocation records 21 integrated families and 420 public
method-development tasks; the next locked family is
`nested-json-schema-migration`.

These assets are deliberately public, unsealed, unscored, and
nonauthorizing. A passing fixed reviewed Bash canary demonstrates engineering
feasibility only. It does not authorize arbitrary candidate execution,
research model selection, or a model-quality claim.

The near-term critical path is therefore:

1. finish and independently review the remaining development families;
2. close the general-candidate sandbox and runtime trust gates;
3. freeze evaluation identities and complete corpus admission;
4. run backbone and capability-support feasibility gates;
5. screen the operator funnel under matched budgets; and
6. promote only locked winners to fresh-seed and sealed confirmation.

## Where details live

- [PLAN.md](PLAN.md): authoritative scientific design and thresholds.
- [EXPERIMENT_SETUP_RATIONALE.md](EXPERIMENT_SETUP_RATIONALE.md): concise
  research-level claim and failure-mode rationale.
- [EXPERIMENT_LOGIC.md](EXPERIMENT_LOGIC.md): dependency graph and result
  interpretation rules.
- [EXPERIMENT_COMPONENTS.md](EXPERIMENT_COMPONENTS.md): shorter conceptual
  component inventory.
- [EXPERIMENT_EVIDENCE_CHAIN.md](EXPERIMENT_EVIDENCE_CHAIN.md): detailed
  evidence produced at each stage.
- [RESEARCH_READINESS.md](RESEARCH_READINESS.md): build state versus evidence
  state.
- [EXPERIMENT_INFRASTRUCTURE.md](EXPERIMENT_INFRASTRUCTURE.md): technical
  execution and trust boundaries.
- [IMPLEMENTATION.md](IMPLEMENTATION.md): live implementation ledger.
