# Experiment components and why they matter

This is the short conceptual guide to the experiment. It explains the role of
each major component, the failure it is meant to prevent, and how the pieces
fit together. For the full research design, see [PLAN.md](PLAN.md). For the
short research-level rationale, see
[EXPERIMENT_SETUP_RATIONALE.md](EXPERIMENT_SETUP_RATIONALE.md). For the
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

The current public method-development allocation is locked at 25 families and
500 tasks. Twenty-three families/460 tasks have concrete oracles and 2,300
fixture bundles across fourteen additive tranches; two families/40 tasks
remain planned, beginning with `process-lifecycle-delta`. The
coverage ledger fixes
the remaining semantic grids so implementation cannot silently chase easy
families, but it is an allocation—not completion, human review, sealing,
candidate-execution authority, scoring, or model-selection evidence. All
current development assets remain public, unsealed, unscored, and
nonauthorizing; independent human review remains unattested, and V1 invocation
still admits only the frozen first tranche.

Coverage v1 is retained byte-for-byte as historical evidence. Its exploratory
hardlink grid contained redundant, nondeterministic, and nonorthogonal cells.
The [migration record](configs/executable-method-development-coverage-v1-to-v2-migration.json)
binds the replacement grid, the 20-signature discrimination evidence, and the
fact that all other 24 family records are unchanged.
Coverage v2 is likewise retained byte-for-byte. The
[v2-to-v3 migration](configs/executable-method-development-coverage-v2-to-v3-migration.json)
promotes only the previously planned archive family, preserves its locked
axes and contract, binds the tenth integration evidence, and proves that the
other 24 family records are unchanged.
Coverage v3 is retained byte-for-byte in turn. The
[v3-to-v4 migration](configs/executable-method-development-coverage-v3-to-v4-migration.json)
promotes only `checksum-repair-plan`, preserves its locked axes and contract,
binds the eleventh integration evidence, and again proves that the other 24
family records are unchanged. Coverage v4 is likewise retained byte-for-byte.
The v4-to-v5 migration promotes only `jsonl-csv-enrichment-compose`, binds the
twelfth integration evidence, preserves the first two promotion records, and
proves the other 24 family records unchanged. The historical v4
semantic/config-byte SHA-256
values are
`1bd7a4b6ab721404f1d1eb7a64718ba7df783998bf16cd603afb86eb2420d67c`
and `d003a5748da855257aa93e0c6e1b7a4be2de393ec5faa0dcb32d74156f40b3d7`
for 24,590 canonical bytes. The migration semantic/config-byte SHA-256 values
are
`667e31ef974829a5114544b1f1164f25c0f7515f67ef5600c979e85a3bcc3d8b`
and `a1a783544d76f471688afe5f45eaf0f16c30a6ce04c36d1d5a438d6c8e439b7f`
for 4,701 canonical bytes.
The historical v5 semantic/config-byte SHA-256 values are
`e5987525654e384c2696908bf147e8224ad3bdc1fb2e0bbc3856a4f23cdca8b9`
and `cfb91bef706fc1c4fd4f95d7891f42e3ec058bbaba28997a22a0f72614d6268f`
for 25,241 canonical bytes. Its v4-to-v5 migration semantic/config-byte
SHA-256 values are
`7119bbf14ae74047a555483fc7e6e3a9d74ce46cdcb741a13aa5da34a66e1cea`
and `f1d4566d17c7b51b3649000f896272ca56ec2f6d32fe5563aa4751c4a6fa563f`
for 5,052 canonical bytes.
The
[v5-to-v6 migration](configs/executable-method-development-coverage-v5-to-v6-migration.json)
promotes only `nested-json-schema-migration`, binds
the thirteenth integration evidence, preserves the first three promotion
records, and proves the other 24 family records unchanged. The historical
[v6 lock](configs/executable-method-development-coverage-v6.json)
semantic/config-byte SHA-256 values are
`044f026b67a531613b1034b27056f1b6f91e1d95ae8902108428e67a6a9c31cf`
and `e526485ba7b34c0325ff6809dcee428c251cd25dd34e907ca3b2eff56c174d68`
for 25,899 canonical bytes. Its v5-to-v6 migration semantic/config-byte
SHA-256 values are
`5c345bc6860f5c9ff70dba656d3cc1204acb705a0d2c4526b4031364313d7e90`
and `31f99bd95165b44cdd5aa4d9bc668b1fcf559a1d621a56c14c80a8d1c5521a8e`
for 5,423 canonical bytes.
The current
[v7 lock](configs/executable-method-development-coverage-v7.json) promotes
only `dependency-dag-execution-plan`, binds the fourteenth integration
evidence, preserves the first four promotion records, and proves the other 24
family records unchanged through its
[v6-to-v7 migration](configs/executable-method-development-coverage-v6-to-v7-migration.json).
The v7 semantic/config-byte SHA-256 values are
`177a97767a528db74951a191282f6d719a34c8a136a21086940dfbd92e5bb569`
and `3742f632c7b5b18f8851d8ce198fe6eebd6ae6dbb1e3cf68a37633d67452f7bc`
for 26,558 canonical bytes. The migration semantic/config-byte SHA-256 values
are
`7b1822b390fae8c78bf991d0b348b7033a6d0e33e6fa2318ecdf5a0ae060bee8`
and `ee03276d08386a52a1220bba8de4b6d25a245ab550d4c278c29cef0a1bcf2adc`
for 5,744 canonical bytes.

The [sixth-tranche manifest](reports/executable-sixth-tranche/manifest.json)
binds the `bounded-retry-state-machine` task set, added registry, cumulative
suite, additive catalog, and canonical report bytes with SHA-256 values
`112e9d079a1b21b2d371e61d48af2401649b23aeff11a45e4d2dcbe847e1541c`,
`14280b3cbc8a96c919a57a325b5795c381cba86b2a31934f7069821b7ff4e3c4`,
`db6d00278664f5a72834ebf0297411564da8b98a75d08eb2c2e9cf706dc985b1`,
`9042968ead33dd098870d21582bc3114706d3af3841bdb3ab7a0d40c5727d990`,
and `3661d9fe60d78de51bf518fff32282b437b770515c7bbb9a1263072dfb0d13ac`.
The [seventh-tranche manifest](reports/executable-seventh-tranche/manifest.json)
binds the `case-routed-batch-transform` task set, added registry, cumulative
suite, additive catalog, and canonical 56,368-byte report with SHA-256 values
`e68a7e4614424e76fa35d4c0650e500469b971f1a5010d309115b0c225b7b2e6`,
`14aa05939c2ac2f4954196968003254dee39175f1d1d94e32213b8a74cfff19e`,
`341b50a83305a9e0c64ada387eee461209ca75d1083e34fe2887a608179de131`,
`99dcf8918151a5a87bdeea8f51bde8ad6e10063b46419a334d7d8b211310e6d8`,
and `49c17168813721bc9f66213f4e5b6dd873d97aadd0afd0839a3533a77f7251d9`.
The [eighth-tranche manifest](reports/executable-eighth-tranche/manifest.json)
binds the `collision-safe-batch-rename` task set, added registry, cumulative
suite, additive catalog, and canonical `56,369`-byte report
with SHA-256 values
`6c563074579359d666faaae2aebf69019c74521e8946cea6a2fe19a756c744cd`,
`8ef6879c5b6f4198c1b0ff2acfcffe89b6cbdd418a9aa2af2eefedfb12994736`,
`b22742179e3ce3b7331469de9db0a75ddbae81a3340e2b814c8a7ab34233f0f0`,
`05e4b90408a0970dfded597e5ee7813386bfdaed50a1cea301148eaabd83c297`,
and `822f2e20e5f73d638dff810c12aec0985145b642801975f6148b034ecf155d0e`.
The [ninth-tranche manifest](reports/executable-ninth-tranche/manifest.json)
binds the `hardlink-deduplicated-mirror` task set, added registry, cumulative
suite, cumulative catalog, discrimination evidence, and canonical 56,392-byte
report. The corresponding SHA-256 values are
`0415daa5f9bccfcd75b621ef4ae71c9e79a5b7c19763ceb470e5ef21169706d1`,
`ff886754b054445a90ad30197d004e4071dba72bf0af17931d05e461c7e90703`,
`d0647e24f29abd59f8c2d6b2ac2a404aee78b92c780f8be4f9b16d200885843b`,
`56932666f2641b5947e1801378b233dd5f37f568e4f2b4c6aa171bad115b09d8`,
`1a0c0d23bb262c1d94250a92574c89af6c6333da08d58be715e1b5d1f4940435`,
and `8bb43dfa235261ab5e237b26a5384d767a02ad351a8b3311fc909ad860b70b6b`.
The [tenth-tranche manifest](reports/executable-tenth-tranche/manifest.json)
binds the `compressed-archive-roundtrip-verify` task set, added registry,
cumulative suite, cumulative catalog, discrimination evidence, and canonical
56,553-byte report. The corresponding SHA-256 values are
`450ba507f0672e3a47ca6d495a6553d07294c605f94b3c5f03aa111d42bf771a`,
`0d07fd82de275ffd9dc274b97a6fa02fdd0620f83d5ee90a2bea0ad64f06f0ab`,
`629119116c53a0be2cc7cacb5461ae13de7d50f29b0a129707a840089ab48d2f`,
`5a29ea69111028fe69322d892e061a723ab53fb857ce4077cca924e314a4f4d6`,
`ae95eef5802c010e70e338d257f5d0f3d01a39fa5cf471f945a8b75f554faa21`,
and `02442d60bf7d7874016fc9d50857cd49f9d8e1342ece55a42d7c8afcd852f0fb`.
The
[eleventh-tranche manifest](reports/executable-eleventh-tranche/manifest.json)
binds the `checksum-repair-plan` task set, added registry, cumulative suite,
cumulative catalog, discrimination evidence, and canonical 56,202-byte
report. The corresponding SHA-256 values are
`e52fb74ece2a94baa9bd1b2f6da25ca103839e1e9666361fe5406c34a36b9bb0`,
`bd0c14880eb25fa80100c317fa41086c45c59147407a67f03981831bcfdfc100`,
`f62ba1c1214fc48f194a5dea9c69c04962cc14dbdccfc38640cf4eee833018cb`,
`cd4221870ba4bfd5ade5098bddccc15af47865930bf173f05141194f3e0b8177`,
`f71ba70f0a4d004bed235e897a73c1222c6d2687e4eeb842c008f7878e9457aa`,
and `d6916730cd81170f067b0669812063fd4071102494fd56174b01672b5cad0d59`.
The
[twelfth-tranche manifest](reports/executable-twelfth-tranche/manifest.json)
binds the `jsonl-csv-enrichment-compose` task set, added registry, cumulative
suite, cumulative catalog, behavioral-discrimination evidence, and canonical
56,394-byte report. The corresponding SHA-256 values are
`60a8ab6770bae6de43d430db9e3edf136f28f0a0ad2dacfd09b627ce19cf75c3`,
`a9733f220a7bdfb8435841eff875c9fd7b1dbadbee6de2d2aa0646750164f862`,
`32ec82cf193f364946def16462e52217176093d0a3f6399d574c9faf66eaa4a1`,
`98cf6ffa48cbe11ece96195450335e5be9a3d0898d54e91396d0c2756171f169`,
`732c1438a4337d2043ee85e2eb4e9e7c437a0051eb1a828cdac6139845db0e94`,
and `792bb1a4116d6698cc07cebfa6edef9c6358ccd4fe497d99703e88ed81262103`.
The
[thirteenth-tranche manifest](reports/executable-thirteenth-tranche/manifest.json)
binds the `nested-json-schema-migration` task set, added registry, cumulative
suite, cumulative catalog, behavioral-discrimination evidence, and canonical
56,396-byte report. The corresponding SHA-256 values are
`2ab692e66a3090b5d05a204b18f4fdb99ddc822cdbaa5b7912b7ac2166680e0b`,
`01990ca4355ef20736861d7bb7753e09e5ccbbfbddf8d21c4ffce3a451d83873`,
`bb7b78b68879eb32d4849bb5d82cac7a90b0695dc3fa72b9836dd7b6e70863e0`,
`25142ebdc014f4d4a53bba34bb9ffeaffa6f87789169180fe0caab69b02fcb9f`,
`416907543c373f36e55098c514fbe17aeef0192d9e5dc43cd025bed809a0ad42`,
and `0250c1e3134d342c57378f0fb8a3b6c4c06ae84ca4fdee4dcda743eefcff8fb7`.
The
[fourteenth-tranche manifest](reports/executable-fourteenth-tranche/manifest.json)
binds the `dependency-dag-execution-plan` task set, added registry, cumulative
suite, cumulative catalog, label-free behavioral discrimination, and canonical
56,419-byte report. The corresponding frozen SHA-256 values are
`57860e84d15ba33575b12b365f1f541b2537051a12e45f3ca470f1d14819c279`,
`c79de716570fe600f2dd7b1e3569456e6f42774d70143a309809410ad8097709`,
`497aac2c69daf2ff05e28b1f132090f3a380ce8ce215b63869a846d576616cf9`,
`11b25fb47af89945a80080b6c42d2fe315076384f3929555c1909cd7c318534b`,
`25c9f68985ed918a6e8fe9d36b4b6d8a9bd34bb2cd9b039dff82a9276658c82c`,
and `731f3ff9d03befb25ee72a5ed7ea13a17cd30aedfe60cd0d84df9aed5276a490`.
The preserved v1 coverage and config-byte identities are
`6c215d9eaf5581aaa146d6814a9d40621a57459c5af98ae4ca625caff10c9c8c`
and `46f98f54ef5682ce0adc3854557ecfe8ed092fd5e916935bc27702edb4e86efa`;
the backward-linked v2 coverage identity is
`7406480a1dc06bc99d1e36fde1a328a490d6cc8d6b96ee38c924a902acbf9abd`.
The preserved v3 semantic/config-byte SHA-256 values are
`b37f48c98e7216c78ddf74d0ce6f6d74cd095575f20f53de6bf30018b2180d79`
and `de241ad1e4536fa595f99acf0ef05a3e423418876298c576abe87249c018bc0a`
for 23,943 bytes. The v2-to-v3 migration semantic/config-byte SHA-256
values are
`8e36252576376d86ddb0a4f3b399dfdd66377b0ed026369bbf799edf104818a2`
and `77820327bc105d367d8d737c110e53e8183ce786650ecb4c1699991412cb6683`
for 4,358 bytes.

The fifth `pipefail-atomic-report` family makes an important evaluator
distinction concrete. Its exact semantics model complete logical streams, the
ordered configured status vector, and five success/failure publication
policies; its final-state verifier checks the required report or absence and
the complete workspace. Checked-in tests exercise two semantic constructions,
all fixtures, randomized valid streams, and mutations without executing a
candidate program. A final-state check still cannot prove that an atomic rename
occurred, Bash `PIPESTATUS` supplied the vector, a claimed pipeline topology
ran, or only allowed tools were used.
It therefore requires trusted quiescence and makes no claim about global
quiescence, directory-permission errors, or live effective-access failures.

The sixth `bounded-retry-state-machine` family distinguishes success,
transient failure, ordinary failure, and terminal failure across linear,
branching, bounded-cyclic, and compensating workflows. Its five retry policies
have distinct one-, two-, four-, and six-attempt per-state-visit behavior;
budgets reset on each visit, ordinary failure separates transient-only from
the broader retry policies, and terminal failure always stops retrying. Exact
attempt and terminal reports expose routes, revisits, compensation, missing
events, and causes. They remain extensional evidence: final-state verification
cannot show that the candidate actually retried, waited, traversed states,
compensated, used only allowed tools, published atomically, preserved inputs
throughout execution, exited as claimed, or was globally quiescent. A trusted
supervisor is required, and directory-permission/live-access failures remain
uncovered.

The seventh `case-routed-batch-transform` family makes multi-record shell
branching concrete. A manifest loop classifies each logical record using one
of four exclusive signals, applies a byte-exact transform, and handles
unmatched records under one of five batch policies. Independent parsing,
routing, transformation, and serialization paths must agree; the verifier
then authenticates the inputs and exact complete final tree. This remains
extensional evidence: it cannot prove route, transform, read-scope, tool,
atomic-publication, exit-status, transient-input, or global-quiescence history.
A fixed source-reviewed Bash implementation passes all 100 public fixtures
under a restricted tool `PATH`, including a separate binary-stream case. That
canary establishes feasibility for one hand-authored program, not a caller-
selected candidate API, production sandbox, scored result, model-selection
result, or scientific claim.

The eighth `collision-safe-batch-rename` family adds genuine source-tree
mutation. Four destination rules cross five collision policies, including
whole-batch rejection, collision skipping, stable winners, and byte-identical
coalescing. The oracle records every source disposition, and the workspace
verifier checks both sides of the mutation: moved and coalesced sources must be
absent; rejected sources, collision losers, the mapping, symlink distractors,
and other input leaves must remain exact. Original directories preserve kind,
mode, and link topology, while child-removal changes to their size and
modification time are nonsemantic. Published representatives must preserve
bytes, permission mode, modification time, and link count one. A fixed
source-reviewed Bash canary passes all 20 rule/policy cells on a binary profile,
and its Bash-only byte comparator distinguishes a single-byte mutation at every
position of the 0–255 byte corpus plus empty, NUL, newline, and invalid-UTF-8
boundary cases. This demonstrates that the contract is implementable with the
locked tool set;
it does not authorize generated programs or prove rename, collision-decision,
staging, atomic-publication, crash, inode, read-scope, tool, exit-status, or
global-quiescence history. The final-state verifier therefore still requires a
trusted supervisor to establish quiescence.

The ninth `hardlink-deduplicated-mirror` family makes physical topology part
of correctness. Four content/metadata equivalence keys cross five
deterministic owner policies. Partition and owner probes make every one of the
20 cells distinguishable before registry admission. Fixtures include
pre-existing input aliases, source mtimes, binary and empty files, hostile
names, modes, and symlink distractors. Separately structured parsing and
grouping paths agree before shared owner and final-state assembly, after which
the verifier checks exact output bytes, modes, mtimes, link counts, portable
hardlink groups, the complete ledger, and input preservation. A fixed reviewed
Bash program passes all 100 public fixtures under the exact seven-tool `PATH`.
This is development feasibility and verifier evidence only; it cannot prove
creation history, tool history, transient state, global quiescence, exit
status, sealed generalization, or model performance.

The tenth `compressed-archive-roundtrip-verify` family composes normalized
ustar creation, one of four outer encodings, exact reconstruction, and one of
five evidence projections. Its trusted decoder admits exactly one bounded
gzip, bzip2, xz, or uncompressed stream under the closed format contract; its
ustar parser checks ordered regular members, bytes, modes, and normalized
metadata without extracting untrusted names. The workspace verifier then
checks the candidate-derived relational report, reconstructed file bytes,
modes, zero mtimes, link count one, output closure, and input preservation. A
fixed reviewed Bash canary passes all 100 public fixtures with exactly the
seven declared utilities. These observations establish final-state
feasibility and verifier sensitivity. They do not establish the commands,
verification order, temporary checks, causal reconstruction path, transient
state, global quiescence, or exit status of a future candidate.

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

1. implement the locked 2-family/40-task remainder, beginning with
   `process-lifecycle-delta`, and independently review
   the complete executable development benchmark;
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
