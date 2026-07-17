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
  and 500 tasks. Twenty-three families/460 tasks currently have concrete
  oracles and 2,300 authenticated fixture bundles across fourteen additive
  tranches.
- These development assets are public, unsealed, unscored, and
  nonauthorizing. The coverage lock is an allocation commitment, not proof of
  implementation, independent human review, candidate execution, or model
  quality.
- The remaining 2 families/40 tasks, beginning with
  `process-lifecycle-delta`, still need implementation and review.
- General untrusted-candidate execution, independent human benchmark audit,
  sealed suites, claim-eligible corpus admission, backbone qualification,
  operator training, fresh-seed confirmation, and final hardware results are
  not yet complete.

The live and more granular status is always [IMPLEMENTATION.md](IMPLEMENTATION.md).
The historical thirteenth-tranche allocation and its exact content identity
are in
[coverage v6](configs/executable-method-development-coverage-v6.json). Its
[v5-to-v6 migration](configs/executable-method-development-coverage-v5-to-v6-migration.json)
preserves exact v5 bytes and proves that only the
thirteenth family was promoted. The v6 semantic/config-byte SHA-256 values are
`044f026b67a531613b1034b27056f1b6f91e1d95ae8902108428e67a6a9c31cf`
and `e526485ba7b34c0325ff6809dcee428c251cd25dd34e907ca3b2eff56c174d68`
for 25,899 canonical bytes. The migration semantic/config-byte SHA-256 values
are
`5c345bc6860f5c9ff70dba656d3cc1204acb705a0d2c4526b4031364313d7e90`
and `31f99bd95165b44cdd5aa4d9bc668b1fcf559a1d621a56c14c80a8d1c5521a8e`
for 5,423 canonical bytes.
The current public allocation is
[coverage v7](configs/executable-method-development-coverage-v7.json). Its
[v6-to-v7 migration](configs/executable-method-development-coverage-v6-to-v7-migration.json)
preserves exact v6 bytes and proves that only the fourteenth family was
promoted. The v7 semantic/config-byte SHA-256 values are
`177a97767a528db74951a191282f6d719a34c8a136a21086940dfbd92e5bb569`
and `3742f632c7b5b18f8851d8ce198fe6eebd6ae6dbb1e3cf68a37633d67452f7bc`
for 26,558 canonical bytes. The migration semantic/config-byte SHA-256 values
are
`7b1822b390fae8c78bf991d0b348b7033a6d0e33e6fa2318ecdf5a0ae060bee8`
and `ee03276d08386a52a1220bba8de4b6d25a245ab550d4c278c29cef0a1bcf2adc`
for 5,744 canonical bytes.
The original [v1 record](configs/executable-method-development-coverage-v1.json)
and [v2 record](configs/executable-method-development-coverage-v2.json) are
preserved byte-for-byte. The
[migration evidence](configs/executable-method-development-coverage-v1-to-v2-migration.json)
proves that only the hardlink family declaration changed in v2, while the
[v2-to-v3 migration evidence](configs/executable-method-development-coverage-v2-to-v3-migration.json)
proves that v3 changes only the archive family's lifecycle and bound
integration evidence. Its semantic SHA-256 is
`8e36252576376d86ddb0a4f3b399dfdd66377b0ed026369bbf799edf104818a2`;
its 4,358 canonical bytes have SHA-256
`77820327bc105d367d8d737c110e53e8183ce786650ecb4c1699991412cb6683`.

The sixth
[`bounded-retry-state-machine` manifest](reports/executable-sixth-tranche/manifest.json)
binds 20 tasks and 100 fixtures. Its task-set, registry, cumulative-suite,
catalog, and report-byte SHA-256 values are
`112e9d079a1b21b2d371e61d48af2401649b23aeff11a45e4d2dcbe847e1541c`,
`14280b3cbc8a96c919a57a325b5795c381cba86b2a31934f7069821b7ff4e3c4`,
`db6d00278664f5a72834ebf0297411564da8b98a75d08eb2c2e9cf706dc985b1`,
`9042968ead33dd098870d21582bc3114706d3af3841bdb3ab7a0d40c5727d990`,
and `3661d9fe60d78de51bf518fff32282b437b770515c7bbb9a1263072dfb0d13ac`.
The family separates transient, ordinary, and terminal failures across five
retry policies: fixed and until-terminal policies retry transient and ordinary
failures, transient-only retries only transient failures, terminal failure
always stops retrying, and every state/visit gets a fresh budget. Exact reports bind
branches, bounded cycles, compensation, missing events, and causes. These are
final-state semantics only: the verifier does not observe actual retries,
waits, state traversal, compensation, tool use, atomic publication, transient
input preservation, global quiescence, or candidate exit status. The manifest
is public, unsealed, unscored, nonauthorizing, outside first-tranche-only V1
invocation, and records `independent_human_review_attested: false`.

The seventh
[`case-routed-batch-transform` manifest](reports/executable-seventh-tranche/manifest.json)
binds 20 tasks and 100 fixtures. Four exclusive route keys cross five fallback
policies, and separately structured parsers, routers, byte transforms, and
serializers must agree on the status/error records and exact final output tree.
Its task-set, registry, cumulative-suite, catalog, and 56,368-byte report
SHA-256 values are
`e68a7e4614424e76fa35d4c0650e500469b971f1a5010d309115b0c225b7b2e6`,
`14aa05939c2ac2f4954196968003254dee39175f1d1d94e32213b8a74cfff19e`,
`341b50a83305a9e0c64ada387eee461209ca75d1083e34fe2887a608179de131`,
`99dcf8918151a5a87bdeea8f51bde8ad6e10063b46419a334d7d8b211310e6d8`,
and `49c17168813721bc9f66213f4e5b6dd873d97aadd0afd0839a3533a77f7251d9`.
The verifier checks authenticated final state but not actual routing,
transformation, read scope, tool use, atomic publication, transient input
preservation, global quiescence, or exit status. One fixed source-reviewed Bash
program passes all 100 public fixtures under a restricted tool `PATH`; this is
a feasibility canary, not a caller-selected candidate API, production sandbox,
scored result, model-selection result, or research claim. The family remains
public, unsealed, unscored, nonauthorizing, outside first-tranche-only V1
invocation, and records `independent_human_review_attested: false`.

The eighth
[`collision-safe-batch-rename` manifest](reports/executable-eighth-tranche/manifest.json)
binds 20 tasks and 100 fixtures. Four rename rules cross five collision
policies, and independently structured engines agree on the per-source action
plan, flat output tree, exact ledger, and representative metadata. Its task-
set, registry, cumulative-suite, catalog, and
`56,369`-byte report SHA-256 values are
`6c563074579359d666faaae2aebf69019c74521e8946cea6a2fe19a756c744cd`,
`8ef6879c5b6f4198c1b0ff2acfcffe89b6cbdd418a9aa2af2eefedfb12994736`,
`b22742179e3ce3b7331469de9db0a75ddbae81a3340e2b814c8a7ab34233f0f0`,
`05e4b90408a0970dfded597e5ee7813386bfdaed50a1cea301148eaabd83c297`,
and `822f2e20e5f73d638dff810c12aec0985145b642801975f6148b034ecf155d0e`.
The mutation-aware verifier checks expected source removal/retention, exact
retained leaves, directory kind/mode/link topology, exact output bytes, and
representative size/mode/mtime under trusted quiescence. It cannot establish
actual rename or inode identity, collision decisions, read scope, tool use,
staging or atomic-publication history, crash rollback, transient input
preservation, global quiescence, or candidate exit status. One fixed source-
reviewed Bash program realizes all 20 rule/policy cells on the binary profile
under a restricted tool `PATH`, with a separate all-byte/NUL equality probe.
This is engineering feasibility, not a caller-selected candidate API,
production sandbox, scored result, model-selection result, or research claim.
The family remains public, unsealed, unscored, nonauthorizing, outside first-
tranche-only V1 invocation, and records
`independent_human_review_attested: false`.

The ninth
[`hardlink-deduplicated-mirror` manifest](reports/executable-ninth-tranche/manifest.json)
binds 20 tasks and 100 fixtures whose correctness includes real shared-inode
topology. Four equivalence keys cross five deterministic owner policies, and
dedicated probes make all 20 cells distinguishable. Separately structured
parsing and grouping paths must agree before shared final-state assembly; the
verifier checks exact bytes, modes, mtimes, input preservation, link counts,
portable hardlink groups, and the complete ledger. A fixed
reviewed Bash program passes all 100 public fixtures using only the declared
seven external tools. This is feasibility and verifier evidence, not candidate
authorization, a score, model selection, or a research result.

The tenth
[`compressed-archive-roundtrip-verify` manifest](reports/executable-tenth-tranche/manifest.json)
binds another 20 tasks and 100 fixtures. Four outer encodings cross five
closed evidence-report projections, while every cell retains the same strict
inner-ustar and reconstructed-tree semantics. The verifier decodes exactly one
bounded stream, rejects truncation, concatenation and trailing data, parses
ustar bytes without extraction, checks the complete output tree and preserved
inputs, and derives report evidence from the candidate artifact. A fixed
reviewed Bash program passes all 100 public fixtures under the declared
seven-tool `PATH`. Final state cannot establish the candidate's actual
verification sequence, tool history, transient paths, causal derivation of
the round-trip tree, global quiescence, or exit status. The canary establishes
public-development feasibility only.
The task-set, registry, cumulative-suite, cumulative-catalog, discrimination,
and canonical 56,553-byte report SHA-256 values are
`450ba507f0672e3a47ca6d495a6553d07294c605f94b3c5f03aa111d42bf771a`,
`0d07fd82de275ffd9dc274b97a6fa02fdd0620f83d5ee90a2bea0ad64f06f0ab`,
`629119116c53a0be2cc7cacb5461ae13de7d50f29b0a129707a840089ab48d2f`,
`5a29ea69111028fe69322d892e061a723ab53fb857ce4077cca924e314a4f4d6`,
`ae95eef5802c010e70e338d257f5d0f3d01a39fa5cf471f945a8b75f554faa21`,
and `02442d60bf7d7874016fc9d50857cd49f9d8e1342ece55a42d7c8afcd852f0fb`.

## Where the detailed answers live

- [PLAN.md](PLAN.md): authoritative scientific protocol and success thresholds.
- [EXPERIMENT_LOGIC.md](EXPERIMENT_LOGIC.md): dependency graph, claim ladder,
  and interpretation rules.
- [EXPERIMENT_COMPONENTS.md](EXPERIMENT_COMPONENTS.md): detailed conceptual
  guide to individual components.
- [EXPERIMENT_INFRASTRUCTURE.md](EXPERIMENT_INFRASTRUCTURE.md): trust boundaries,
  runtime isolation, artifact contracts, and evidence plumbing.
- [HARDLINK_EXPERIMENT_INFRASTRUCTURE.md](HARDLINK_EXPERIMENT_INFRASTRUCTURE.md):
  the ninth tranche's topology model, coverage migration, and failure modes.
- [ARCHIVE_ROUNDTRIP_EXPERIMENT_INFRASTRUCTURE.md](ARCHIVE_ROUNDTRIP_EXPERIMENT_INFRASTRUCTURE.md):
  the tenth tranche's codec/archive boundary, relational report, canary, and
  v2-to-v3 promotion.
- [CHECKSUM_REPAIR_EXPERIMENT_INFRASTRUCTURE.md](CHECKSUM_REPAIR_EXPERIMENT_INFRASTRUCTURE.md):
  the eleventh tranche's manifest grammars, declarative repair semantics,
  verifier, canary, and v3-to-v4 promotion.
- [JSONL_CSV_ENRICHMENT_EXPERIMENT_INFRASTRUCTURE.md](JSONL_CSV_ENRICHMENT_EXPERIMENT_INFRASTRUCTURE.md):
  the twelfth tranche's strict mixed-codec sources, join and missing-field
  semantics, verifier, canary, and v4-to-v5 promotion.
- [NESTED_JSON_SCHEMA_MIGRATION_EXPERIMENT_INFRASTRUCTURE.md](NESTED_JSON_SCHEMA_MIGRATION_EXPERIMENT_INFRASTRUCTURE.md):
  the thirteenth tranche's strict nested JSON, migration policies, verifier,
  Python-permitted canary, and v5-to-v6 promotion.
- [DEPENDENCY_DAG_EXECUTION_PLAN_EXPERIMENT_INFRASTRUCTURE.md](DEPENDENCY_DAG_EXECUTION_PLAN_EXPERIMENT_INFRASTRUCTURE.md):
  the fourteenth tranche's strict graph encodings, deterministic Kahn
  policies, exact cycle classification, and v6-to-v7 promotion.
- [EXPERIMENT_EVIDENCE_CHAIN.md](EXPERIMENT_EVIDENCE_CHAIN.md): how component
  outputs compose into claim-eligible evidence.
- [RESEARCH_READINESS.md](RESEARCH_READINESS.md): compact build-state versus
  evidence-state assessment.
- [IMPLEMENTATION.md](IMPLEMENTATION.md): mutable implementation ledger and
  critical path.
