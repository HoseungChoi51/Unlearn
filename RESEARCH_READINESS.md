# Experiment setup: importance and research readiness

This document is the status-aware map of the experiment. It explains why each
major component exists, what is implemented now, and what still prevents that
component from supporting a model-quality claim. The scientific protocol and
thresholds live in [PLAN.md](PLAN.md); the detailed task ledger lives in
[IMPLEMENTATION.md](IMPLEMENTATION.md). Exact current digests and byte counts
live in the [artifact identity ledger](ARTIFACT_IDENTITY_LEDGER.md); this file
uses its stable human-readable artifact names.

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
| Generator-backed benchmark | Tests semantic programs and edge cases rather than prompt-template similarity | 480 integrated public-development tasks/2,400 fixtures across fifteen additive tranches; the backward-linked 25-family/500-task allocation is locked | Gated: 1 family/20 tasks remains planned, independent human review is unfinished, and no sealed suite exists | Implement the locked remainder, review the complete inventory, then build closed ID/OOD suites |
| Lifecycle splits and leakage control | Stops training, selection, and repeated inspection from consuming the final test set | Split contracts and fail-closed lifecycle routing exist | Partial | Freeze real suite identities and generate prompt/AST/graph/trace leakage reports |
| Parser and deterministic decoding | Fixes how one model response becomes one candidate and prevents rerun policy from changing scores | Frozen response parser and diagnostic syntax classification exist | Partial: production decoder/action loop is absent | Freeze generation settings and implement the bounded static and interactive decoders |
| Runtime closure, sandbox, and supervisor | Lets untrusted code run against identical tools without reaching the host or surviving a timeout | Namespace, descriptor, runtime-bundle, PID1, and one reviewed fixed-Bash canary exist | Gated: arbitrary candidates, exact Bash tool policy, external trust, and runtime-data closure are absent | Promote an independently reviewed general-candidate boundary with tmpfs/quiescence/resource guarantees |
| Oracle and semantic verifier | Decides whether output and filesystem state satisfy the task rather than merely resemble a reference string | Mutation checks exist for twenty-four integrated families, with independently structured oracle paths where available; topology, archive, checksum, mixed-codec composition, nested Python-permitted migration, dependency-DAG planning, and static process-lifecycle deltas receive family-specific checks | Gated: family coverage and stratified human review are incomplete | Finish semantic coverage, mutation audit, and external human review before sealing |
| Production trainer and operator funnel | Determines empirically whether dense tuning, pruning, factorization, quantization, or reset/regrow offers the best performance/size tradeoff | A real-text dense-SFT engineering canary and prospective operator schemas exist | Planned for research runs | Implement production training/export, then screen matched operators instead of assuming SwiGLU channels win |
| Model-aware operator binding | Prevents out-of-range indices, partial GQA groups, fictitious pruning savings, or misleading average-bit claims | Prospective exact binding covers tensor roles/factorization tuples, representable pruning, and quantization payload lower bounds; completed floating-dense reconciliation rejects wrong architecture dimensions for supported pruning | Gated: exact selected-unit/value realization, embedding-map replay, residual/hidden physical pruning, and factorized/quantized/hybrid exporters remain absent | Add exporter-specific topology and mapping replay before accepting operator realization |
| Baselines and causal interventions | Separates useful specialization from extra compute, random plasticity, sparse tuning, or generic compression | Prospective arms and interpretation rules exist | Planned | Run matched dense, random, target-only, no-reset, uniform-quantization, restoration, and add-back controls |
| Statistics and claim acceptance | Fixes direction, uncertainty, multiplicity, non-inferiority, and success thresholds before results are known | Paired confirmatory statistics and fail-closed claim interfaces are implemented | Gated: they have no eligible source outcome chain | Derive all inputs from registry-bound task collections and reopen every upstream artifact |
| Export and portable hardware measurement | Tests whether nominal compression produces real byte, memory, latency, or throughput gains | Schemas and a reproducible measurement protocol exist | Planned for experimental artifacts | Reopen the exact export, pass correctness, and collect raw repeated hardware samples |
| Immutable provenance | Makes models, data, tasks, masks, seeds, outputs, and reports auditable as one chain | Content-addressed manifests and registries exist across many stages; supported completed source/export artifacts can be freshly reopened into a companion record | Partial: saved runtime reports are unauthenticated and downstream claim binders do not yet require/reopen every companion source | Publish prospective commitments externally and complete end-to-end source reopening |

The preserved v1 development allocation has semantic SHA-256
`6c215d9eaf5581aaa146d6814a9d40621a57459c5af98ae4ca625caff10c9c8c`
and canonical config-byte SHA-256
`46f98f54ef5682ce0adc3854557ecfe8ed092fd5e916935bc27702edb4e86efa`.
The backward-linked v2 allocation has semantic SHA-256
`7406480a1dc06bc99d1e36fde1a328a490d6cc8d6b96ee38c924a902acbf9abd`
and promotes only the fully discriminable hardlink family, leaving 24 family
records unchanged. It remains immutable historical evidence. The historical
[v3 allocation](configs/executable-method-development-coverage-v3.json)
preserves the exact v2 bytes and promotes only
`compressed-archive-roundtrip-verify`; its
[migration record](configs/executable-method-development-coverage-v2-to-v3-migration.json)
proves the other 24 family records remain unchanged. It is a scope commitment,
not benchmark completion: it grants no fixture, review, sealing, execution,
scoring, selection, or claim status to planned families. Coverage v4 promotes
only `checksum-repair-plan`. Coverage v5 promotes only
`jsonl-csv-enrichment-compose`. Historical coverage v6 promotes only
`nested-json-schema-migration`; historical coverage v7 promotes only
`dependency-dag-execution-plan`; current coverage v8 promotes only
`process-lifecycle-delta`, leaving `symlink-aware-tree-reconcile` as the one
remaining locked family.
The v3 semantic/config-byte SHA-256 values are
`b37f48c98e7216c78ddf74d0ce6f6d74cd095575f20f53de6bf30018b2180d79`
and `de241ad1e4536fa595f99acf0ef05a3e423418876298c576abe87249c018bc0a`
for 23,943 canonical bytes. The v2-to-v3 migration semantic/config-byte
SHA-256 values are
`8e36252576376d86ddb0a4f3b399dfdd66377b0ed026369bbf799edf104818a2`
and `77820327bc105d367d8d737c110e53e8183ce786650ecb4c1699991412cb6683`
for 4,358 canonical bytes.
The historical
[v4 allocation](configs/executable-method-development-coverage-v4.json) has
semantic/config-byte SHA-256 values
`1bd7a4b6ab721404f1d1eb7a64718ba7df783998bf16cd603afb86eb2420d67c`
and `d003a5748da855257aa93e0c6e1b7a4be2de393ec5faa0dcb32d74156f40b3d7`
for 24,590 canonical bytes. Its
[v3-to-v4 migration](configs/executable-method-development-coverage-v3-to-v4-migration.json)
has semantic/config-byte SHA-256 values
`667e31ef974829a5114544b1f1164f25c0f7515f67ef5600c979e85a3bcc3d8b`
and `a1a783544d76f471688afe5f45eaf0f16c30a6ce04c36d1d5a438d6c8e439b7f`
for 4,701 canonical bytes.
The historical
[v5 allocation](configs/executable-method-development-coverage-v5.json) has
semantic/config-byte SHA-256 values
`e5987525654e384c2696908bf147e8224ad3bdc1fb2e0bbc3856a4f23cdca8b9`
and `cfb91bef706fc1c4fd4f95d7891f42e3ec058bbaba28997a22a0f72614d6268f`
for 25,241 canonical bytes. Its
[v4-to-v5 migration](configs/executable-method-development-coverage-v4-to-v5-migration.json)
has semantic/config-byte SHA-256 values
`7119bbf14ae74047a555483fc7e6e3a9d74ce46cdcb741a13aa5da34a66e1cea`
and `f1d4566d17c7b51b3649000f896272ca56ec2f6d32fe5563aa4751c4a6fa563f`
for 5,052 canonical bytes.
The historical
[v6 allocation](configs/executable-method-development-coverage-v6.json) has
semantic/config-byte SHA-256 values
`044f026b67a531613b1034b27056f1b6f91e1d95ae8902108428e67a6a9c31cf`
and `e526485ba7b34c0325ff6809dcee428c251cd25dd34e907ca3b2eff56c174d68`
for 25,899 canonical bytes. Its
[v5-to-v6 migration](configs/executable-method-development-coverage-v5-to-v6-migration.json)
has semantic/config-byte SHA-256 values
`5c345bc6860f5c9ff70dba656d3cc1204acb705a0d2c4526b4031364313d7e90`
and `31f99bd95165b44cdd5aa4d9bc668b1fcf559a1d621a56c14c80a8d1c5521a8e`
for 5,423 canonical bytes.
The historical
[v7 allocation](configs/executable-method-development-coverage-v7.json) has
semantic/config-byte SHA-256 values
`177a97767a528db74951a191282f6d719a34c8a136a21086940dfbd92e5bb569`
and `3742f632c7b5b18f8851d8ce198fe6eebd6ae6dbb1e3cf68a37633d67452f7bc`
for 26,558 canonical bytes. Its
[v6-to-v7 migration](configs/executable-method-development-coverage-v6-to-v7-migration.json)
has semantic/config-byte SHA-256 values
`7b1822b390fae8c78bf991d0b348b7033a6d0e33e6fa2318ecdf5a0ae060bee8`
and `ee03276d08386a52a1220bba8de4b6d25a245ab550d4c278c29cef0a1bcf2adc`
for 5,744 canonical bytes.
The current
[v8 allocation](configs/executable-method-development-coverage-v8.json) has
the semantic identity `coverage v8` and exact-file identity
`coverage v8 config file` in the
[artifact identity ledger](ARTIFACT_IDENTITY_LEDGER.md#fifteenth-tranche-and-coverage-v8).
Its
[v7-to-v8 migration](configs/executable-method-development-coverage-v7-to-v8-migration.json)
has the semantic identity `coverage v7-to-v8 migration` and exact-file
identity `coverage v7-to-v8 migration config file` in the same ledger.

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

The eighth [`collision-safe-batch-rename`
manifest](reports/executable-eighth-tranche/manifest.json) adds 20 tasks and
100 fixtures. Four rename rules cross five collision policies; independently
structured engines agree on each source's destination, disposition,
representative, exact ledger, and flat output tree. Its task-set, registry,
cumulative-suite, catalog, and `56,369`-byte report
SHA-256 values are `6c563074579359d666faaae2aebf69019c74521e8946cea6a2fe19a756c744cd`,
`8ef6879c5b6f4198c1b0ff2acfcffe89b6cbdd418a9aa2af2eefedfb12994736`,
`b22742179e3ce3b7331469de9db0a75ddbae81a3340e2b814c8a7ab34233f0f0`,
`05e4b90408a0970dfded597e5ee7813386bfdaed50a1cea301148eaabd83c297`,
and `822f2e20e5f73d638dff810c12aec0985145b642801975f6148b034ecf155d0e`.
The mutation-aware verifier checks absent moved/coalesced sources, exact
retained leaves, input-directory kind/mode/link topology, exact outputs, and
representative size/mode/mtime under trusted quiescence. It does not observe
actual rename or inode identity, collision decisions, read scope, tool use,
staging or atomic publication, crash rollback, transient input preservation,
global quiescence, or candidate exit status. A fixed source-reviewed Bash
program passes all 20 rule/policy cells on the binary profile under a
restricted tool `PATH`, and an equality probe covers all byte values and NUL
boundaries. That canary is not an arbitrary-candidate API, production
sandbox, score, selection result, or research claim. The assets remain public,
unsealed, unscored, nonauthorizing, outside first-tranche-only V1 invocation,
and record `independent_human_review_attested: false`.

The ninth `hardlink-deduplicated-mirror` addition contributes 20 tasks and 100
fixtures whose correctness includes physical inode sharing. Four equivalence
keys cross five deterministic owner policies, and dedicated partition/owner
probes yield 20 distinct fixture-oracle-derived signatures. Separately
structured dictionary-partition and sorted-stream parsing/grouping paths agree
before shared final-state assembly. The verifier checks exact bytes, modes,
mtimes, input preservation, link counts, and portable hardlink-group
identities; a fixed reviewed Bash program passes all 100 public fixtures with
the exact seven-tool allowlist. This establishes development feasibility and
verifier sensitivity, not a production sandbox, model score, model-selection
result, or research claim. Trusted quiescence, external tool/runtime trust,
sealed generalization, and independent human review remain open gates.

The tenth `compressed-archive-roundtrip-verify` addition contributes 20 tasks
and 100 fixtures. Four outer formats cross five report projections. Every
policy still requires one bounded selected-format stream, strict normalized
ustar members, exact reconstructed bytes/modes/zero mtimes, link count one,
output closure, a candidate-derived relational report, and stable inputs.
Codec truncation, concatenation, trailing data, wrong-format artifacts,
archive/member/report mutations, unsafe paths, and final-workspace mutations
are rejected. A fixed reviewed Bash implementation passes all 100 public
fixtures using only the declared seven utilities. This establishes
development feasibility and verifier sensitivity, not a production sandbox,
model score, model-selection result, or research claim. The final-state check
cannot establish actual verification steps, tool use, operation order,
temporary state, causal reconstruction, global quiescence, or exit status.
The task-set, registry, cumulative-suite, cumulative-catalog, discrimination,
and canonical 56,553-byte report SHA-256 values are
`450ba507f0672e3a47ca6d495a6553d07294c605f94b3c5f03aa111d42bf771a`,
`0d07fd82de275ffd9dc274b97a6fa02fdd0620f83d5ee90a2bea0ad64f06f0ab`,
`629119116c53a0be2cc7cacb5461ae13de7d50f29b0a129707a840089ab48d2f`,
`5a29ea69111028fe69322d892e061a723ab53fb857ce4077cca924e314a4f4d6`,
`ae95eef5802c010e70e338d257f5d0f3d01a39fa5cf471f945a8b75f554faa21`,
and `02442d60bf7d7874016fc9d50857cd49f9d8e1342ece55a42d7c8afcd852f0fb`.

The twelfth `jsonl-csv-enrichment-compose` addition contributes 20 tasks and
100 fixtures. Four source/intermediate codec layouts cross five missing-field
policies. Two semantic paths agree on strict parsing, nonjoinable filled IDs,
duplicate-key Cartesian multiplicity, rejection behavior, and ordered final
JSONL; a fixed reviewed Bash implementation passes all 100 public fixtures
with the declared four utilities. All-100 workspace and boundary tests
establish development feasibility and verifier sensitivity, not a production
sandbox, model score, model-selection result, or research claim. The
final-state check cannot establish physical intermediate materialization,
tool use, read scope, operation order, atomicity, transient state, global
quiescence, or exit status. The task-set, registry, cumulative-suite,
cumulative-catalog, discrimination, and canonical 56,394-byte report SHA-256
values are
`60a8ab6770bae6de43d430db9e3edf136f28f0a0ad2dacfd09b627ce19cf75c3`,
`a9733f220a7bdfb8435841eff875c9fd7b1dbadbee6de2d2aa0646750164f862`,
`32ec82cf193f364946def16462e52217176093d0a3f6399d574c9faf66eaa4a1`,
`98cf6ffa48cbe11ece96195450335e5be9a3d0898d54e91396d0c2756171f169`,
`732c1438a4337d2043ee85e2eb4e9e7c437a0051eb1a828cdac6139845db0e94`,
and `792bb1a4116d6698cc07cebfa6edef9c6358ccd4fe497d99703e88ed81262103`.

The thirteenth `nested-json-schema-migration` addition contributes 20 tasks
and 100 fixtures on the Python-permitted track. Four bounded source shapes
cross five exact v1-to-v2 migration policies. Independent construction paths,
strict parser and tree mutations, and a fixed Bash wrapper using embedded
`python3 -I -S` cover all 100 public fixtures. This establishes development
feasibility and verifier sensitivity, not Python confinement, a production
sandbox, model score, model-selection result, or research claim. The task-set,
registry, cumulative-suite, cumulative-catalog, discrimination, and canonical
56,396-byte report SHA-256 values are
`2ab692e66a3090b5d05a204b18f4fdb99ddc822cdbaa5b7912b7ac2166680e0b`,
`01990ca4355ef20736861d7bb7753e09e5ccbbfbddf8d21c4ffce3a451d83873`,
`bb7b78b68879eb32d4849bb5d82cac7a90b0695dc3fa72b9836dd7b6e70863e0`,
`25142ebdc014f4d4a53bba34bb9ffeaffa6f87789169180fe0caab69b02fcb9f`,
`416907543c373f36e55098c514fbe17aeef0192d9e5dc43cd025bed809a0ad42`,
and `0250c1e3134d342c57378f0fb8a3b6c4c06ae84ca4fdee4dcda743eefcff8fb7`.

The fourteenth `dependency-dag-execution-plan` addition contributes 20 tasks
and 100 fixtures on the Python-permitted track. Four strict graph encodings
cross five exact Kahn ready-node policies. Independent planning paths,
parser/workspace mutations, and a fixed Bash wrapper using embedded
`python3 -I -S` cover all 100 public fixtures. This establishes development
feasibility and verifier sensitivity, not Python confinement, a production
sandbox, model score, model-selection result, or research claim. The task-set,
registry, cumulative-suite, cumulative-catalog, discrimination, and canonical
56,419-byte report SHA-256 values are
`57860e84d15ba33575b12b365f1f541b2537051a12e45f3ca470f1d14819c279`,
`c79de716570fe600f2dd7b1e3569456e6f42774d70143a309809410ad8097709`,
`497aac2c69daf2ff05e28b1f132090f3a380ce8ce215b63869a846d576616cf9`,
`11b25fb47af89945a80080b6c42d2fe315076384f3929555c1909cd7c318534b`,
`25c9f68985ed918a6e8fe9d36b4b6d8a9bd34bb2cd9b039dff82a9276658c82c`,
and `731f3ff9d03befb25ee72a5ed7ea13a17cd30aedfe60cd0d84df9aed5276a490`.

The fifteenth `process-lifecycle-delta` addition contributes 20 tasks and 100
fixtures on the Bash-native track. Four bounded synthetic process projections
cross five transition-selection policies. Independent raw-input parsers and
state derivations, workspace mutations, and a fixed source-reviewed Bash
program cover all 100 public fixtures. This establishes static
method-development feasibility and verifier sensitivity, not live-process
monitoring, a production sandbox, model score, model-selection result, or
research claim. Its distinct semantic and file identities are published as
the fifteenth-tranche entries in the
[artifact identity ledger](ARTIFACT_IDENTITY_LEDGER.md#fifteenth-tranche-and-coverage-v8).

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
- [ARCHIVE_ROUNDTRIP_EXPERIMENT_INFRASTRUCTURE.md](ARCHIVE_ROUNDTRIP_EXPERIMENT_INFRASTRUCTURE.md)
  owns the tenth family's codec/archive semantics, canary boundary, and
  publication identities.
- [IMPLEMENTATION.md](IMPLEMENTATION.md) is the detailed mutable task ledger.
- This document owns the compact build-state/evidence-state synthesis.
- [README.md](README.md) is the repository orientation and command index.
