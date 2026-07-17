# Experiment setup: importance and research readiness

This document is the status-aware map of the experiment. It explains why each
major component exists, what is implemented now, and what still prevents that
component from supporting a model-quality claim. The scientific protocol and
thresholds live in [PLAN.md](PLAN.md); the detailed task ledger lives in
[IMPLEMENTATION.md](IMPLEMENTATION.md).

The research question is deliberately narrow:

> Can a dense language model below one billion physical parameters perform
> executable Unix-terminal work better at the same deployed size, or preserve
> enough performance at a smaller deployed footprint to improve the Pareto
> frontier?

Ability suppression is not a result by itself. A safety change, a forgotten
skill, or a lower score outside the target matters only when it causally helps
terminal performance or a real deployment measurement such as weight bytes,
peak memory, latency, or throughput. The primary campaign is non-MoE. A
sub-1B expert appendix remains disabled unless dense experiments first reveal
reproducible capability clusters and the complete routed network stays below
the same physical-parameter ceiling.

There is no model-quality result yet.

## How to read readiness

Two independent statuses are needed:

- **Build state** asks whether code and verification exist.
- **Evidence state** asks whether the result may enter a research comparison.

An engineering canary can therefore be implemented while remaining gated. For
example, the repository can execute one fixed, reviewed Bash program through a
bounded supervisor, but it does not yet admit arbitrary synthesized programs
for scoring. Likewise, a self-hashed report proves internal consistency, not
that an artifact was externally preregistered or reopened by a claim binder.

The terms used below are:

- **Implemented**: a bounded implementation and tests exist.
- **Partial**: a useful subset exists, but the named component is incomplete.
- **Gated**: implementation exists, but review, identity, admission, isolation,
  or evidence-chain prerequisites forbid research use.
- **Planned**: campaign execution or the component itself is absent.

## End-to-end evidence flow

```text
scientific claim contract
        |
        v
model + tokenizer + data + task identity
        |
        v
backbone feasibility + capability-support gates
        |
        v
matched training/compression operator funnel
        |
        v
isolated executable evaluation on frozen fixtures
        |
        v
paired statistics + protected-capability checks
        |
        v
exact export + portable hardware evidence
        |
        v
bounded interpretation and reproducible release
```

Every link is necessary. Better training cannot repair a leaked benchmark;
sound statistics cannot repair an unsafe or incorrect evaluator; fewer nominal
parameters do not establish a smaller or faster deployment.

## Component readiness matrix

| Component | Why it matters | Build state | Evidence state | Next gate |
|---|---|---|---|---|
| Claim contract and measurement lanes | Keeps fixed-size specialization separate from compression and prevents ability loss from being called success | Implemented | Gated: no campaign outcome exists | Preserve the frozen thresholds through the first behavioral runs |
| Dense sub-1B checkpoint qualification | Establishes the exact network, tensor shapes, physical parameters, precision, tokenizer, and operator bounds being compared | Implemented for exact static Qwen2, Qwen3, and Llama Safetensors, including a narrow completed source/export companion | Partial: fresh static completion reconciliation exists, but saved runtime evidence is passive and the binding remains nonauthorizing | Add attested runtime graph/value evidence and broader export formats |
| Backbone feasibility | Ensures the starting model is neither at target floor nor ceiling and can actually improve | Engineering GPU fit pilots exist | Planned for behavior; no backbone is selected | Run executable floor/ceiling gates on admitted development tasks |
| Capability-support and signed-transfer audit | Finds abilities that help, hurt, or do not affect terminal work instead of guessing from labels | Contracts and interpretation rules exist | Planned | Measure above-floor capabilities, cross-fit interventions, and add-back effects |
| Training-source admission | Prevents invalid, ambiguous, unlicensed, duplicated, or evaluation-contaminated examples from driving a false gain | Raw import, authentication, lexical filtering, and tokenizer scheduling are implemented | Gated: zero rows are claim-admitted | Add Bash parsing, fixture execution, row lineage, ambiguity repair, balancing, and decontamination |
| Token and compute ledger | Makes equal-target-token and equal-total-FLOP comparisons meaningful | Exact engineering token schedules and update ledgers exist | Partial: production executed-FLOP binding is absent | Derive FLOPs from the actual production operator trace |
| Generator-backed benchmark | Tests semantic programs and edge cases rather than prompt-template similarity | 320 integrated public-development tasks/1,600 fixtures across seven additive tranches; the full 25-family/500-task allocation is locked | Gated: 9 families/180 tasks remain planned, independent human review is unfinished, and no sealed suite exists | Implement the locked remainder, review the complete inventory, then build closed ID/OOD suites |
| Lifecycle splits and leakage control | Stops training, selection, and repeated inspection from consuming the final test set | Split contracts and fail-closed lifecycle routing exist | Partial | Freeze real suite identities and generate prompt/AST/graph/trace leakage reports |
| Parser and deterministic decoding | Fixes how one model response becomes one candidate and prevents rerun policy from changing scores | Frozen response parser and diagnostic syntax classification exist | Partial: production decoder/action loop is absent | Freeze generation settings and implement the bounded static and interactive decoders |
| Runtime closure, sandbox, and supervisor | Lets untrusted code run against identical tools without reaching the host or surviving a timeout | Namespace, descriptor, runtime-bundle, PID1, and one reviewed fixed-Bash canary exist | Gated: arbitrary candidates, exact Bash tool policy, external trust, and runtime-data closure are absent | Promote an independently reviewed general-candidate boundary with tmpfs/quiescence/resource guarantees |
| Oracle and semantic verifier | Decides whether output and filesystem state satisfy the task rather than merely resemble a reference string | Independent constructions and full-catalog mutation checks exist for sixteen integrated families | Gated: family coverage and stratified human review are incomplete | Finish semantic coverage, mutation audit, and external human review before sealing |
| Production trainer and operator funnel | Determines empirically whether dense tuning, pruning, factorization, quantization, or reset/regrow offers the best performance/size tradeoff | A real-text dense-SFT engineering canary and prospective operator schemas exist | Planned for research runs | Implement production training/export, then screen matched operators instead of assuming SwiGLU channels win |
| Model-aware operator binding | Prevents out-of-range indices, partial GQA groups, fictitious pruning savings, or misleading average-bit claims | Prospective exact binding covers tensor roles/factorization tuples, representable pruning, and quantization payload lower bounds; completed floating-dense reconciliation rejects wrong architecture dimensions for supported pruning | Gated: exact selected-unit/value realization, embedding-map replay, residual/hidden physical pruning, and factorized/quantized/hybrid exporters remain absent | Add exporter-specific topology and mapping replay before accepting operator realization |
| Baselines and causal interventions | Separates useful specialization from extra compute, random plasticity, sparse tuning, or generic compression | Prospective arms and interpretation rules exist | Planned | Run matched dense, random, target-only, no-reset, uniform-quantization, restoration, and add-back controls |
| Statistics and claim acceptance | Fixes direction, uncertainty, multiplicity, non-inferiority, and success thresholds before results are known | Paired confirmatory statistics and fail-closed claim interfaces are implemented | Gated: they have no eligible source outcome chain | Derive all inputs from registry-bound task collections and reopen every upstream artifact |
| Export and portable hardware measurement | Tests whether nominal compression produces real byte, memory, latency, or throughput gains | Schemas and a reproducible measurement protocol exist | Planned for experimental artifacts | Reopen the exact export, pass correctness, and collect raw repeated hardware samples |
| Immutable provenance | Makes models, data, tasks, masks, seeds, outputs, and reports auditable as one chain | Content-addressed manifests and registries exist across many stages; supported completed source/export artifacts can be freshly reopened into a companion record | Partial: saved runtime reports are unauthenticated and downstream claim binders do not yet require/reopen every companion source | Publish prospective commitments externally and complete end-to-end source reopening |

The development allocation lock has semantic SHA-256
`cc3e2d4a3bdd9048a6f96cbcaa0b4b823ce5f27430ed020862fca6e731a7fbce`
and canonical config-byte SHA-256
`93e31b2e6f314369866c72be65ba2f2530951ec5e20e0fa1336faf717baee121`.
It is a scope commitment, not benchmark completion: it grants no fixture,
review, sealing, execution, scoring, selection, or claim status to the 9
planned families. The next locked family is `collision-safe-batch-rename`.

The fifth `pipefail-atomic-report` addition contributes 20 tasks and 100
fixtures with exact complete-stream aggregation, ordered status vectors, and
five final publication policies. Its checked-in tests cover two semantic
constructions, catalog materialization, randomized valid streams, and
final-state mutations. This is final-state evidence only: the verifier requires
trusted quiescence and does not observe atomic-rename history, Bash
`PIPESTATUS`, executed topology, tool history, global quiescence, explicit
directory-permission failures, or live effective-access failures. The fifth
manifest, like the other public-development records, is unsealed, unscored,
nonauthorizing, and records no independent human-review attestation; V1
invocation remains first-tranche-only and executes no candidate from this
family.

The sixth [`bounded-retry-state-machine`
manifest](reports/executable-sixth-tranche/manifest.json) adds 20 tasks and 100
fixtures. Its four transition models cross five retry policies with distinct
one-, two-, four-, and six-attempt state-visit behavior, transient-versus-
ordinary retry eligibility, terminal failures that always stop retrying, and
fresh budgets per visit.
The exact attempt/terminal reports cover branch selection, bounded cycles,
compensation, missing events, and causes. Its task-set, registry, cumulative-
suite, catalog, and report-byte SHA-256 values are
`112e9d079a1b21b2d371e61d48af2401649b23aeff11a45e4d2dcbe847e1541c`,
`14280b3cbc8a96c919a57a325b5795c381cba86b2a31934f7069821b7ff4e3c4`,
`db6d00278664f5a72834ebf0297411564da8b98a75d08eb2c2e9cf706dc985b1`,
`9042968ead33dd098870d21582bc3114706d3af3841bdb3ab7a0d40c5727d990`,
and `3661d9fe60d78de51bf518fff32282b437b770515c7bbb9a1263072dfb0d13ac`.
This remains final-state evidence: it cannot establish actual retries, waits,
transitions, compensation, tool use, atomic publication, transient input
preservation, global quiescence, or candidate exit status. The assets are
public, unsealed, unscored, nonauthorizing, outside first-tranche-only V1
invocation, and record `independent_human_review_attested: false`.

The seventh [`case-routed-batch-transform`
manifest](reports/executable-seventh-tranche/manifest.json) adds 20 tasks and
100 fixtures. Four route keys cross five unmatched-record fallback policies;
two separately structured implementations agree on manifest parsing, routing,
byte transforms, error/status records, and the complete output tree. Its task-
set, registry, cumulative-suite, catalog, and 56,368-byte report SHA-256 values
are
`e68a7e4614424e76fa35d4c0650e500469b971f1a5010d309115b0c225b7b2e6`,
`14aa05939c2ac2f4954196968003254dee39175f1d1d94e32213b8a74cfff19e`,
`341b50a83305a9e0c64ada387eee461209ca75d1083e34fe2887a608179de131`,
`99dcf8918151a5a87bdeea8f51bde8ad6e10063b46419a334d7d8b211310e6d8`,
and `49c17168813721bc9f66213f4e5b6dd873d97aadd0afd0839a3533a77f7251d9`.
The verifier observes final state, not route, transform, read-scope, tool,
atomic-publication, exit-status, transient-input, or global-quiescence history.
A fixed source-reviewed Bash program passes all 100 public fixtures under a
restricted tool `PATH`, but that feasibility canary is not an arbitrary-
candidate API, production sandbox, score, selection result, or research claim.
The assets remain public, unsealed, unscored, nonauthorizing, outside first-
tranche-only V1 invocation, and record
`independent_human_review_attested: false`.

## What the architecture-specific gate now establishes

The exact dense checkpoint qualifier closes an important ambiguity left by the
generic artifact inspector. For Qwen2, Qwen3, and Llama it reconstructs every
expected tensor name and shape, rejects missing or extra tensors, rejects
packed/quantized/mixed parameter dtypes, counts tied storage once, and checks
that dtype width, payload bytes, and physical parameter count agree. It emits
model-derived bounds for layers, residual branches, attention heads, FFN
channels, hidden dimensions, vocabulary entries, factorization matrices, and
tensor roles.

The prospective binder then joins that report to a run specification and the
separately self-hashed generic inspection. It binds a locally inspectable,
contiguous tokenizer ID range no larger than the model's embedding vocabulary;
reserved embedding rows are allowed. It also enforces complete Qwen GQA
groups; binds exact factorization tuples; and computes an element-weighted
lower bound for selected plus unselected quantized tensors.

For physical structural compression, the current exact export contract admits
only transformations representable by the supported dense architectures:

- removing complete layers;
- removing the same number of FFN channels from every layer;
- removing the same complete Qwen3 query/KV head groups from every layer; and
- trimming vocabulary rows with an explicit derived vocabulary mapping.

Residual-branch pruning, hidden-dimension pruning, physical Qwen2/Llama head
pruning, and hybrid architectural-plus-quantization exports currently fail
closed. Their index ranges can be described prospectively, but their deployed
parameter savings cannot yet be claimed without a concrete exporter-specific
contract.

The completed-model companion now freshly reopens supported floating-dense
source and export bundles, rebuilds both exact reports, reconciles completion
identity/count/precision/byte fields, and passively validates saved runtime
report structure and aggregate storage/class/vocabulary projections. For
layer, uniform FFN-width, and uniform all-layer Qwen3 complete-GQA-group
head-width pruning it also requires the fresh export to change the planned
architecture dimension; completed
embedding-token pruning fails closed until the derived mapping can be replayed.

That companion is additional evidence, not a replacement for the completed
record. Downstream research use must bind the exact completed-record digest to
the companion digest and reopen its sources; a structurally self-hashed
companion alone is not authoritative. Static architecture deltas do not reveal
which source indices or values populated the export, and saved runtime reports
are neither rerun nor authenticated by this path.

These gates remain passive and permanently nonauthorizing. A self-consistent
report or companion is not a signature and does not prove that a completed run
used those source bytes. Runtime parameter-graph equivalence, exact operator
payload realization, training, selection, scoring, and claim authorization all
remain false.

## Why the remaining gates are ordered

1. **Task identities precede data admission.** Decontamination has no stable
   target until evaluation prompts, program graphs, and fixtures are frozen.
2. **Isolation and verifier trust precede executable scoring.** Otherwise a
   score may measure host leakage, runtime drift, or checker bugs.
3. **Data admission precedes research training.** Authenticated raw bytes are
   not automatically correct, licensed, nonleaking training examples.
4. **Architecture accounting precedes operator claims.** A pruning or
   quantization plan must refer to real tensors and a deployable output.
5. **Feasibility precedes method selection.** Floor and ceiling effects can
   make every operator comparison uninterpretable.
6. **Screening precedes fresh confirmation.** Screening chooses a method;
   confirmation estimates whether it survives new stochastic runs.
7. **Method and analysis lock precede sealed evaluation.** The sealed suite is
   a one-time test, not another tuning split.
8. **Exact export precedes hardware claims.** Runtime measurements must refer
   to the same content-addressed artifact whose accuracy was evaluated.

## What may be claimed today

The repository supports engineering claims about narrow mechanisms: static
artifact inspection, exact architecture qualification for three model
families, bounded passive runtime-report validation, fresh floating-dense
completion reconciliation, reproducible raw-data transformations, token
scheduling, fixed-case runtime integration, verifier mutation behavior, and
statistical contract validation.

It does not yet support claims that:

- one backbone is best;
- any ability is safely expendable for terminal work;
- forgetting, recycling, pruning, factorization, or quantization improves
  performance per size;
- arbitrary synthesized Bash has been safely and correctly scored;
- a compressed artifact is smaller, faster, or more memory efficient in real
  deployment; or
- any public development artifact is sealed evidence.

## Document ownership

- [PLAN.md](PLAN.md) owns the scientific protocol, thresholds, and scope.
- [EXPERIMENT_COMPONENTS.md](EXPERIMENT_COMPONENTS.md) explains the conceptual
  role of each component in more depth.
- [EXPERIMENT_EVIDENCE_CHAIN.md](EXPERIMENT_EVIDENCE_CHAIN.md) explains how
  component evidence composes and why adjacent checks cannot substitute for
  one another.
- [EXPERIMENT_LOGIC.md](EXPERIMENT_LOGIC.md) owns dependency and interpretation
  logic.
- [EXPERIMENT_INFRASTRUCTURE.md](EXPERIMENT_INFRASTRUCTURE.md) owns detailed
  trust boundaries and evidence plumbing.
- [IMPLEMENTATION.md](IMPLEMENTATION.md) is the detailed mutable task ledger.
- This document owns the compact build-state/evidence-state synthesis.
- [README.md](README.md) is the repository orientation and command index.
