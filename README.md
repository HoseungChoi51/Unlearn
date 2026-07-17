# Capability-Budgeted Dense Specialization

Research workspace for improving Unix-terminal performance per unit of model
capacity in dense language models with fewer than one billion parameters.

The project compares fixed-size post-training with task-aware structural and
deployment compression. It does not treat safety-oriented suppression or
ability loss as a result unless target performance or deployed footprint
improves.

- [Research plan](PLAN.md)
- [Short experiment setup overview](EXPERIMENT_SETUP_OVERVIEW.md)
- [Why each experiment component matters](EXPERIMENT_SETUP_IMPORTANCE.md)
- [High-level experiment setup component map](EXPERIMENT_SETUP_COMPONENT_MAP.md)
- [Why the experiment setup is built this way](EXPERIMENT_SETUP_RATIONALE.md)
- [Experiment logic and claim dependencies](EXPERIMENT_LOGIC.md)
- [Experiment components and their roles](EXPERIMENT_COMPONENTS.md)
- [Experiment evidence chain and component rationale](EXPERIMENT_EVIDENCE_CHAIN.md)
- [Experiment setup and research readiness](RESEARCH_READINESS.md)
- [Experiment infrastructure guide](EXPERIMENT_INFRASTRUCTURE.md)
- [Hardlink experiment infrastructure](HARDLINK_EXPERIMENT_INFRASTRUCTURE.md)
- [Compressed archive round-trip experiment infrastructure](ARCHIVE_ROUNDTRIP_EXPERIMENT_INFRASTRUCTURE.md)
- [Checksum repair-plan experiment infrastructure](CHECKSUM_REPAIR_EXPERIMENT_INFRASTRUCTURE.md)
- [JSONL/CSV enrichment-composition experiment infrastructure](JSONL_CSV_ENRICHMENT_EXPERIMENT_INFRASTRUCTURE.md)
- [Implementation status](IMPLEMENTATION.md)
- [Portable hardware benchmarking guide](HARDWARE.md)
- [Hardware result JSON Schema](hardware-result.schema.json)
- [Experiment manifest JSON Schema](experiment-manifest.schema.json)
- [Prospective run-spec JSON Schema](run-spec.schema.json)
- [Immutable campaign-policy JSON Schema](campaign-policy.schema.json)
- [PLAN-derived campaign policy](configs/campaign-policy.json)
- [Cross-run campaign-registry JSON Schema](campaign-registry.schema.json)
- [Prospective evaluation-spec JSON Schema](evaluation-spec.schema.json)
- [Per-task result JSON Schema](task-result.schema.json)
- [Non-claiming GPU engineering pilot](reports/engineering-pilot/manifest.json)
- [Non-claiming corpus/token-schedule pilot](reports/engineering-data-pilot/manifest.json)
- [Non-claiming dense-SFT canary](reports/engineering-dense-sft-canary/manifest.json)
- [Executable first-tranche hash manifest](reports/executable-first-tranche/manifest.json)
- [Executable additive second-tranche hash manifest](reports/executable-second-tranche/manifest.json)
- [Executable additive third-tranche hash manifest](reports/executable-third-tranche/manifest.json)
- [Executable additive fourth-tranche hash manifest](reports/executable-fourth-tranche/manifest.json)
- [Executable additive fifth-tranche hash manifest](reports/executable-fifth-tranche/manifest.json)
- [Executable additive sixth-tranche hash manifest](reports/executable-sixth-tranche/manifest.json)
- [Executable additive seventh-tranche hash manifest](reports/executable-seventh-tranche/manifest.json)
- [Executable additive eighth-tranche hash manifest](reports/executable-eighth-tranche/manifest.json)
- [Executable additive ninth-tranche hash manifest](reports/executable-ninth-tranche/manifest.json)
- [Executable additive tenth-tranche hash manifest](reports/executable-tenth-tranche/manifest.json)
- [Executable additive eleventh-tranche hash manifest](reports/executable-eleventh-tranche/manifest.json)
- [Executable additive twelfth-tranche hash manifest](reports/executable-twelfth-tranche/manifest.json)
- [Executable additive thirteenth-tranche hash manifest](reports/executable-thirteenth-tranche/manifest.json)
- [Nested JSON migration component guide](NESTED_JSON_SCHEMA_MIGRATION_EXPERIMENT_INFRASTRUCTURE.md)
- [Current executable method-development coverage lock](configs/executable-method-development-coverage-v6.json)
- [Coverage v5-to-v6 migration evidence](configs/executable-method-development-coverage-v5-to-v6-migration.json)
- [Historical executable coverage v5 record](configs/executable-method-development-coverage-v5.json)
- [Coverage v4-to-v5 migration evidence](configs/executable-method-development-coverage-v4-to-v5-migration.json)
- [Historical executable coverage v4 record](configs/executable-method-development-coverage-v4.json)
- [Coverage v3-to-v4 migration evidence](configs/executable-method-development-coverage-v3-to-v4-migration.json)
- [Historical executable coverage v3 record](configs/executable-method-development-coverage-v3.json)
- [Coverage v2-to-v3 migration evidence](configs/executable-method-development-coverage-v2-to-v3-migration.json)
- [Historical executable coverage v2 record](configs/executable-method-development-coverage-v2.json)
- [Coverage v1-to-v2 migration evidence](configs/executable-method-development-coverage-v1-to-v2-migration.json)
- [Superseded executable coverage v1 record](configs/executable-method-development-coverage-v1.json)

## Quick start

The current foundation has no mandatory third-party runtime dependencies. Use
the development extra when running the repository's full test suite:

```bash
python3 -m pip install -e '.[dev]'
cbds prepare \
  --config configs/benchmark-smoke.json \
  --output-dir data/generated/smoke
python3 -m unittest discover -s tests -v
cbds train \
  --run-spec examples/run-spec.example.json \
  --campaign-policy configs/campaign-policy.json \
  --output runs/example-plan.json \
  --dry-run
cbds validate-experiment-record \
  --run-spec examples/run-spec.example.json \
  --campaign-policy configs/campaign-policy.json \
  --manifest examples/experiment-manifest.example.json
cbds validate-evaluation-spec \
  --evaluation-spec examples/evaluation-spec.example.json \
  --experiment-manifest examples/experiment-manifest.example.json
cbds validate-run-spec \
  --run-spec examples/run-spec.example.json
```

The logical-corpus commands authenticate a pinned raw import and replay its
deterministic transformation. They deliberately do not imply that rows are
safe, correct, executable, licensed at row level, decontaminated, or admitted
for a research run:

```bash
cbds prepare-training-corpus \
  --config configs/training-corpus-pilot.json \
  --source-root /path/to/pinned/NL2SH-ALFA/snapshot \
  --output-dir data/generated/backbone-pilot-corpus
cbds verify-training-corpus \
  --corpus-dir data/generated/backbone-pilot-corpus \
  --source-root /path/to/pinned/NL2SH-ALFA/snapshot \
  --expected-corpus-sha256 CORPUS_SHA256 \
  --expected-manifest-sha256 MANIFEST_SHA256 \
  --require-authenticated
cbds prepare-training-source-audit \
  --audit-id nl2sh-alfa-lexical-v1 \
  --corpus-dir data/generated/backbone-pilot-corpus \
  --source-root /path/to/pinned/NL2SH-ALFA/snapshot \
  --expected-corpus-sha256 CORPUS_SHA256 \
  --expected-corpus-manifest-sha256 CORPUS_MANIFEST_SHA256 \
  --output-dir data/generated/training-source-audits/nl2sh-lexical
cbds verify-training-source-audit \
  --audit-dir data/generated/training-source-audits/nl2sh-lexical \
  --expected-audit-sha256 AUDIT_SHA256 \
  --expected-audit-manifest-sha256 AUDIT_MANIFEST_SHA256 \
  --raw-corpus-dir data/generated/backbone-pilot-corpus \
  --raw-source-root /path/to/pinned/NL2SH-ALFA/snapshot \
  --expected-corpus-sha256 CORPUS_SHA256 \
  --expected-corpus-manifest-sha256 CORPUS_MANIFEST_SHA256
cbds prepare-token-schedule \
  --config configs/token-schedule-qwen3-engineering.json \
  --corpus-dir data/generated/backbone-pilot-corpus \
  --corpus-source-root /path/to/pinned/NL2SH-ALFA/snapshot \
  --tokenizer-root /path/to/pinned/Qwen3-0.6B-Base/snapshot \
  --model-embedding-rows 151936 \
  --output-dir data/generated/token-schedules/qwen3-engineering
cbds verify-token-schedule \
  --schedule-dir data/generated/token-schedules/qwen3-engineering \
  --corpus-dir data/generated/backbone-pilot-corpus \
  --corpus-source-root /path/to/pinned/NL2SH-ALFA/snapshot \
  --tokenizer-root /path/to/pinned/Qwen3-0.6B-Base/snapshot \
  --model-embedding-rows 151936 \
  --expected-schedule-sha256 SCHEDULE_SHA256 \
  --expected-manifest-sha256 MANIFEST_SHA256
```

The tokenizer-aware scheduling commands require the optional `runtime` extra.
They additionally reconstruct every selected
occurrence and fixed-length pack, use response-plus-EOS labels, and prove
exact non-padding input-token budgets. The checked-in Qwen3 engineering
record contains 1.6M target and 0.4M support tokens in 2,007 1,024-token
packs. It is an engineering canary input only: `target_policy_accepted`,
`research_training_authorized`, and `research_claim_authorized` are all false.
The source-audit command never invokes a shell or candidate utility. Even audit
pins are insufficient for authenticated consumption: verification must rebuild
the complete artifact from the doubly pinned raw source. On the current raw
import, 4,748/40,533 rows survive the conservative lexical prefilter and remain
non-executed static candidates; no survivor is admitted for research training.

Install the optional local model runtime only on a reviewed ML host:

```bash
python3 -m pip install -e '.[runtime]'
cbds probe-model-runtime \
  --artifact-dir /path/to/flat-safetensors-model \
  --prompt-file configs/runtime-smoke-prompt.txt \
  --token-cap 64 \
  --device cuda:0 \
  --output /tmp/model-runtime-report.json
```

The runtime command first completes strict static inspection, rejects custom
Python/`auto_map` code, forces local-only Safetensors loading with remote code
disabled, accounts tied physical storage once, performs one bounded
non-generative forward pass, and reinspects the bundle afterward. It hashes
the prompt but does not retain its text or the host path in the report. Like
the maintainer microfit below, this library-level local-only policy does not
provide process-level socket isolation.

`scripts/gpu_microfit.py` is a maintainer-only engineering utility for use from
a reviewed repository checkout; it is intentionally not installed as a wheel
module or console command. Its synthetic token IDs are reproducible from the
recorded seed, but it does not enforce bitwise-deterministic CUDA optimization
and its Hugging Face offline/local-only settings do not provide OS-level socket
isolation.

`scripts/dense_sft_canary.py` is the corresponding real-text, full-model
engineering runner. It accepts only an externally pinned model inspection and
an exact source-replayed token schedule; caller-supplied examples, token IDs,
labels, or data order are not accepted. It normalizes accumulated gradients by
the actual supervised-token count, writes a hash-chained update ledger, exports
the dense model under a separate `model/` directory, and reopens every file,
logical tensor, model inspection identity, and source pin before and after
atomic no-replace publication. The source schedule must retain its explicit
engineering-only status, and every completion hard-codes campaign, selection,
and claim eligibility to false.

Use `configs/benchmark-plan.json` only when the full 20,250-record semantic
scaffold is wanted. Generated data, run outputs, and model artifacts are
ignored by Git; their cryptographic identities belong in experiment
manifests. The small files under `reports/engineering-pilot/` are an explicit
versioned exception: they are synthetic fit diagnostics with `claim_scope:
none`, not benchmark or model-selection results.

Files under `examples/` contain synthetic revisions, hashes, accounting,
and artifact identities. They exercise validation only and must not be used as
real experimental provenance. The campaign-registry example illustrates the
strict document shape; joint registry validation additionally requires every
referenced run spec, completed record, evaluation spec, and declared result
collection. Prospective run specs use schema version 2.0.0;
completed records use version 2.0.0 and must carry the canonical run-spec hash.
Evaluation specs and task results use schema version 3.0.0. The checked-in
evaluation example is deliberately an unsealed method-development contract,
not a miniature sealed test.
Planning and completion both require the externally pinned campaign policy;
the validators emit its digest and selected profile. The paired validator
checks immutable commitments, actual token counts, and measured FLOPs against
the prospective ceilings.
The campaign-registry validator joins the complete prospective and completed
run roster. It enforces exact replicate coverage, paired seeds and data,
stable per-arm run protocols, one verified teacher corpus per cohort,
within-cohort uniqueness and cross-phase field-wise freshness for model-
initialization, data-order, training, and operator-selection seeds, declared
promotion links, two-arm confirmatory lanes whose ordered reference/comparison
roles are derived from every prospective run spec's
`campaign.contrast_role`,
and one artifact-bound evaluation per declared suite and run. It verifies the
integrity of the declared roster; the current campaign policy does not encode
enough evidence to prove that an arm deserved promotion or a backbone won the
pilot.
This makes a registry-only role reversal invalid while preserving
operator-neutral controls. It is not a substitute for external preregistration:
run-spec hashes must be immutably published, timestamped, or otherwise trusted
before execution, because an actor able to rewrite the run specs and every
completed binding can author a different prospective campaign.
`cbds validate-run-spec` is the deliberately non-campaign route for validating
pure PTQ/pruning and other calibration-only diagnostic specs; its output says
`campaign_qualified: false` and never represents an experiment arm.

`cbds evaluate` is a hash-only host diagnostic, not a scored evaluator. It
requires `--evaluation-spec`, derives response size, syntax timeout, and
program language from that contract, retains no generated plaintext, and
never executes candidate code. `cbds inspect-model --artifact-dir MODEL_DIR`
performs dependency-free, read-only inspection of a flat local Safetensors
bundle. Any optional report path must be outside `MODEL_DIR` so the report
cannot become part of its own artifact identity.

For the exact static Qwen2/Qwen3/Llama gate, first retain the generic report
and its `report_sha256`, then qualify the unchanged artifact against that
external pin:

```bash
cbds inspect-model \
  --artifact-dir MODEL_DIR \
  --output /tmp/model-inspection.json
cbds qualify-dense-checkpoint \
  --artifact-dir MODEL_DIR \
  --expected-inspection-report-sha256 GENERIC_REPORT_SHA256 \
  --output /tmp/dense-checkpoint.json
```

The second report reconstructs the exact supported tensor inventory, physical
parameter count, dtype/payload consistency, and prospective operator bounds.
It is static, nonauthorizing evidence: it does not prove runtime graph
equivalence, a completed export, model quality, or campaign eligibility. The
library-level dense run-spec binder additionally binds the locally inspected
tokenizer ID range while permitting reserved embedding rows, and reconciles
supported structural, factorization, and
quantization payloads without opening a training or compression path.

After a campaign-valid run has a completed record, the narrow completed-model
companion can reopen both floating-point dense artifacts and reconcile them to
the completion:

```bash
cbds bind-completed-model-evidence \
  --run-spec /path/to/run-spec.json \
  --campaign-policy configs/campaign-policy.json \
  --completed-record /path/to/completed-record.json \
  --source-artifact-dir /path/to/source-model \
  --export-artifact-dir /path/to/exported-model \
  --source-runtime-report /path/to/source-runtime.json \
  --export-runtime-report /path/to/export-runtime.json \
  --output /tmp/completed-model-evidence.json
```

This command freshly inspects exact BF16/F16/F32 Qwen2/Qwen3/Llama
Safetensors source and export bundles. It checks the completed export's
identities, physical accounting, fixed-size or compression rule, planned
vocabulary, and supported layer/uniform-FFN-width/all-layer-Qwen3-GQA-head
architecture deltas. It also
semantically validates and reconciles the supplied saved runtime reports, but
does not rerun or authenticate those observations. Exact selected-unit/value
provenance, runtime parameter-graph equivalence, proof that training consumed
the source bytes, factorized/quantized/hybrid exports, and claim authority
remain explicitly false. The library verifier for an already-built companion
checks only passive structure and its self-hash; it does not reopen artifacts.

For contracts bound to this inspector, `weight_set_sha256` is the weight
artifact identity and `bundle_manifest_sha256` is the complete flat-bundle
identity. `tokenizer.tokenizer_set_sha256` covers the byte-exact recognized
top-level tokenizer, vocabulary, custom-tokenization, and prompt-template
sources listed in the report; unknown companions remain covered only by the
bundle identity. All three are domain-separated canonical inventory hashes,
not interchangeable raw file digests. Evaluation specs additionally pin the
exact prompt-serialization policy independently of those files.
They also commit to a bounded, canonically hashed inventory of opaque task
IDs, task-record hashes, fixture-ID sets, and each task's exact fixture order.
A task result is accepted only when that inventory membership, token/response
limits, per-invocation measurements, aggregate maxima, and task/fixture
commitments match. Later attempts require an execution-only,
content-addressed attempt chain; a complete collection cannot stop at a
retry-eligible result, and its scored selector returns exactly one outcome per
task. Exclusions are fail-closed (`none`) until typed exclusion records and a
manifest binder exist. These validators check committed evidence; they do not
run or independently attest the sandbox measurement harness.

Confirmatory primary contracts additionally pin analysis code identity, RNG
seeds, proportion/percentage-point conversion, crossed seed/task bootstrap,
paired sign-flip randomization, Holm-adjusted p-values, Bonferroni-simultaneous
confidence intervals, non-inferiority margins, success thresholds, and exact
1,000-task sealed-ID or 500-task sealed-OOD suite size. They also pin an
ordered reference/comparison role declaration checked against the campaign
cohort's run-spec-derived projection; the comparison arm must directly source
the reference arm, and the
analysis adapter derives direction from this declaration rather than caller
argument order. `ordered_arm_roles_sha256` is SHA-256 over canonical JSON for
`{"contract":"cbds.ordered-arm-roles","version":"1.0.0","direction":"comparison_minus_reference","ordered_arm_roles":[...]}`.
For reference `dense-sft` and comparison `recycle-ffn`, its fixed digest is
`4d3a4897eb4be2828a0e4f015cf41a29e608a0cfe93991e8214cf36ede795e2c`.
An evaluation spec
binds only its artifact's training seed. Its five-seed set is a prospective
commitment, not proof of five artifacts; multi-seed crossing still requires a
validated campaign registry and complete paired statistics inputs.
The current confirmatory evaluation contract is intentionally static-primary
only. Sealed bounded-interactive ID/OOD suites (planned at 500/250 tasks) need
a separate typed endpoint/count rule and simultaneous non-inferiority binder;
they cannot be labeled confirmatory by this schema yet.
The dependency-free statistics implementation validates the complete paired
arm-by-seed-by-task binary cube and provides a deterministic crossed
bootstrap, paired sign-flip randomization, Holm adjustment, and interval-based
non-inferiority decisions. A schema-locked adapter validates the supplied
evaluation contract and its exact arm/seed/task identities before executing
those methods. The artifact-bound outcome binder derives every binary cell
directly from complete registry-bound scored task-result collections and
immediately runs the contrast without accepting caller-supplied rows. A
separate claim-policy evaluator joins typed statistical, export, matched-token,
matched-FLOP, non-inferiority, hardware, replication, and teacher-free
projections for both lanes. It deliberately keeps `claim_authorized: false`
until seven enumerated source-validator chains reopen and derive those
projections end to end. These are analysis mechanisms, not experimental
results.

`cbds sandbox-preflight --engine podman --image REPO@sha256:DIGEST` performs
only bounded runtime `version`, `info`, and local `image inspect` queries. It
never pulls, creates, starts, or runs a container. Its strongest outcome is
`eligible_for_benign_canary`, which still does not authorize untrusted code.

Hardware-result validation accepts only the exact clean-worktree profiles in
`HARDWARE.md`: five independent cold loads, 10 warmups plus 30 measured
token-controlled repetitions, or one deterministic real-terminal attempt per
prompt and seed. It also enforces timing-measurement presence and sample-count
consistency. Schema validity is only a necessary claim gate; paired completed-
export binding, a passed correctness gate, retained raw samples, and audited
inspection evidence remain required.
Paired binding also fixes hardware `method` and `dose` labels to the completed
operator family and dose.

The checked-in campaign profiles require optimizer adaptation and enforce the
preregistered learning-rate grids by freezing mode: screening uses
2M optimizer-visible tokens, while confirmation and runner-up use 20M, all at
80% target and 20% protected support. Pure post-training quantization or
pruning remains a diagnostic run-spec mode and is not a campaign-qualified arm
until a separate calibration profile and token/provenance ledger are frozen.

## Status

Executable-foundation plus authenticated-data/schedule pilot stage.
Deterministic benchmark
scaffolding and artifact verification, frozen response extraction, local
Safetensors inspection, exact static Qwen2/Qwen3/Llama tensor qualification
and prospective model-aware run-spec binding, sandbox command construction and read-only runtime
preflight, prospective run and scored-evaluation specifications,
completed-record accounting, completed-export evaluation/hardware binding,
fresh floating-dense source/export completion reconciliation with passive
saved-runtime report validation,
cross-document task-result binding, campaign-wide replicate/evaluation
binding, paired confirmatory statistics, collection-derived outcome binding,
fail-closed claim-policy evaluation, and twenty-two cataloged public-development
static fixture/verifier families are implemented across thirteen additive
tranches. The third tranche adds `compound-path-query` and
`regex-log-group-aggregation`; the fourth adds `reproducible-ustar-pack` while
preserving all predecessor identities through exact family-local task and
bundle types; and the fifth adds `pipefail-atomic-report` under the same
additive rule. The sixth adds `bounded-retry-state-machine`, and the seventh
adds `case-routed-batch-transform`. The eighth adds
`collision-safe-batch-rename`; the ninth adds the topology-sensitive
`hardlink-deduplicated-mirror`; and the tenth adds
`compressed-archive-roundtrip-verify`. The eleventh adds
`checksum-repair-plan`; the twelfth adds
`jsonl-csv-enrichment-compose`; and the thirteenth adds
`nested-json-schema-migration`. These additions remain outside the
first-tranche-only V1
invocation protocol. A catalog-admitted
development invocation protocol, bounded runtime-bundle materializer, sealed regular-
payload snapshot, fixed-protocol descriptor-handoff canary, and candidate-input-free
fixed-BusyBox namespace-transfer canary are also implemented. A separate
candidate-input-free native PID1 lifecycle canary covers nine fixed fork,
timeout, output, CPU, seccomp, and spoof scenarios. One frozen first-catalog
fixture and reviewed Bash response are bound into a private, nonexecuting
integration case. A candidate-input-free canary reconstructs that exact
program, fixture, pinned runtime, and policy; rebuilds the fixed native PID1
supervisor; launches the one reviewed case through the rootless
systemd/Bubblewrap envelope; binds a quiescent post-run output projection; and
runs the existing fixture verifier. Its launcher uses a 16 MiB per-file limit
for pinned runtime projection, while native PID1 lowers the Bash child to a
1 MiB `RLIMIT_FSIZE` before exec. This is a reviewed-program execution path,
not a synthesized-candidate API. Runtime-data closure, external trust, general
Bash seccomp and exact-tool enforcement, scoring, model selection, and claim
authority remain false. Evaluation specs validate and
hash prospective contracts; they do not open benchmark assets or execute
candidates. The development fixtures are test assets, not sealed evaluation
data. A bounded public-development namespace/cgroup preflight and
catalog-bound candidate launch-plan builder are implemented, but execution of
synthesized candidates remains blocked until the externally trusted Bash
runtime closure and general supervisor integrate a Bash-specific allow policy
and exact-tool enforcement while preserving cumulative CPU, workspace
quiescence, and scored-outcome binding for arbitrary inputs.
Complete semantic-family coverage, claim-eligible curated data, research
training runs, and research results are not yet present. A 2M-visible-token
Qwen3 dense-SFT canary has completed solely to qualify the training/export
plumbing; it is not a backbone score or campaign run.

The executable-static first tranche contains exactly 100 public
method-development semantic specifications across five families, each paired
with five concrete edge-case profiles: 500 content-bound fixture bundles in
total. The bundles contain real deterministic `FixtureDefinition` inputs and
trusted oracles. Trusted APIs materialize them through descriptor-relative,
no-follow paths and produce content-addressed semantic verifier evidence.
Separate reference constructions are tested for all five families, and the
full-catalog tests materialize and verify the trusted oracle for all 500
bundles without executing candidate code, then show that a one-byte or size
mutation is rejected for every bundle. The checked-in hash-only catalog is
[`reports/executable-first-tranche/manifest.json`](reports/executable-first-tranche/manifest.json),
with registry SHA-256
`ada6043b345e48f69ad602581030aab1bafcb3ff9dc453f9d02342faaf6a7f9a`,
suite SHA-256
`eb64bb4cdb60ab8e0e228f688cf54810fae2ef56768e8b34ac039bdc1aec42ae`,
and catalog SHA-256
`1fc71f89830739a53b69d771b7d0bd6a79a4d78ff698b1c1c2258211e7776c99`.
Its `candidate_execution_authorized`, `model_selection_eligible`, and
`claim_authorized` fields are all hard-coded false.

An additive second tranche contributes another 100 semantic specifications
and 500 bundles across byte-transform mirrors, mode-normalized mirrors, strict
JSONL inner joins, raw POSIX-ustar extraction, and synthetic process-snapshot
reports. It preserves all first-tranche hashes, independently regenerates each
new task/profile answer, and materializes and verifies all 500 added bundles.
The checked-in hash-only additive catalog is
[`reports/executable-second-tranche/manifest.json`](reports/executable-second-tranche/manifest.json),
with added-registry SHA-256
`27e4721036c4870fec463e880cb3a36fcd72ebe530368cb45179f600ee694ab4`,
cumulative-suite SHA-256
`0020c1e5c7907d979d7fa97dead79f199fff59d97184c33fae81bc98df3ef8fb`,
and additive-catalog SHA-256
`e2ad6a3124491bc25410d40278400aeac9cd8791a9f08a530c823d5f14c09e18`.
Its execution, selection, and claim-authority flags are also hard false.

An additive third tranche contributes 40 semantic specifications and 200
bundles across compound path queries and regex-filtered log aggregation. It
preserves both earlier tranche identities by admitting the exact family-local
task and bundle types in a new additive registry and catalog rather than
widening either frozen type contract. The checked-in hash-only report is
[`reports/executable-third-tranche/manifest.json`](reports/executable-third-tranche/manifest.json),
with added-registry SHA-256
`66a9ef43a6387f5f94f511aec3357f0e625427d161a0c6da0d9590a837761237`,
cumulative-suite SHA-256
`3a578668805bbdfdfaf3400483640bb29504591604ed1c9c28cf8f9bb0362fb3`,
and additive-catalog SHA-256
`01554367fd68c36b2f509b8b50b270b0aa7d5e6de3fa55db15a14cf4ec68c26b`.
The canonical report bytes have SHA-256
`58e7e299142bd2c9681f9940f8277489115fa76350ffa53fb984bed81ceac862`.
The manifest explicitly records `independent_human_review_attested: false`;
execution, model-selection, and claim authority also remain false.

An additive fourth tranche contributes 20 semantic specifications and 100
bundles for deterministic POSIX-ustar creation. `reproducible-ustar-pack`
crosses four file selectors with five archive-mode policies and binds a
canonical member order, header normalization, exact member bytes and modes,
and a fixed output-tree policy. Its checked-in trusted constructions, strict
archive parser, workspace verifier, and mutation tests do not execute a model
candidate. A separate implementation-session audit also exercised randomized
differential cases and GNU-tar interoperability; that session result is useful
engineering evidence, but is not yet a checked-in reproducible audit artifact.
The checked-in hash-only report is
[reports/executable-fourth-tranche/manifest.json](reports/executable-fourth-tranche/manifest.json),
with added-registry SHA-256
`3dc5512139361a275afaf0b57b94528961615f9b4eee22ee6c333cc7d8bf4ea5`,
cumulative-suite SHA-256
`668ab9c942888d568c80aaa27bee340ad8a10faf3493a6983bf068d79b134651`,
and additive-catalog SHA-256
`54ff2e17645edfc7887fc39b437340ffe8d736b83001d0265612271c2a3b1d46`.
The canonical report bytes have SHA-256
`a79ba062de86574e95ff60ff4fa8bc48b223c934b70d65ed832da5631359eebb`.
The family-local task-set SHA-256 is
`be044d13053e62e0a9f609e1654048de4c7b422e9bc93c659f0d265ddfd4e283`.

An additive fifth tranche contributes 20 semantic specifications and 100
bundles for deterministic pipeline-status reporting under five publication
policies. `pipefail-atomic-report` crosses four complete-stream logical
pipeline shapes with success-only, status-always, exact rollback, and
first/last-failure publication behavior. The trusted semantics bind the full
ordered stage-status vector, shape-specific aggregate, selected failure, exact
report bytes or absence, and complete final workspace. Its checked-in tests
exercise two separately structured semantic constructions, all catalog
fixtures, final-state mutations, and randomized valid record streams; no
candidate program is executed. The checked-in hash-only report is
[reports/executable-fifth-tranche/manifest.json](reports/executable-fifth-tranche/manifest.json),
with family task-set SHA-256
`fc974695fe967094bcba6c6f8ff8c267c86f64215de78c43a8e693bed1252562`,
added-registry SHA-256
`d562d462814b7fc6413e0e085d16f66def28157c1a6361adf28cd3d42eb5f88c`,
cumulative-suite SHA-256
`27ea8064a72453a4e7a4bc52b125a924139088cd1c20d417a867aa9ddda96e00`,
and additive-catalog SHA-256
`cb24e42fc27500fa5076224dfc195a6fe2a4b08752724f09ff944961aa7221db`.
The canonical 56,246-byte report has SHA-256
`80959058c764da72437bfa1bd01a2eb1c747a221ec1c06f59278c02b80e0ef48`.

An additive sixth tranche contributes 20 semantic specifications and 100
bundles for deterministic bounded-retry workflow reporting.
`bounded-retry-state-machine` crosses linear, branching, bounded-cyclic, and
compensating transition models with five behaviorally distinct retry policies.
The policies allow one, two, four, or six total attempts per state visit;
fixed and until-terminal policies retry transient and ordinary failures,
whereas `retry-transient-only` stops on ordinary failure, and terminal failure
always stops retrying. Retry budgets reset for every state/visit pair. Exact
attempt and terminal reports bind branch selection, bounded revisits,
compensation, empty ledgers, missing events, and the initiating or stopping
cause. Two separately structured constructions must agree before fixture
admission. The checked-in hash-only report is
[reports/executable-sixth-tranche/manifest.json](reports/executable-sixth-tranche/manifest.json),
with family task-set SHA-256
`112e9d079a1b21b2d371e61d48af2401649b23aeff11a45e4d2dcbe847e1541c`,
added-registry SHA-256
`14280b3cbc8a96c919a57a325b5795c381cba86b2a31934f7069821b7ff4e3c4`,
cumulative-suite SHA-256
`db6d00278664f5a72834ebf0297411564da8b98a75d08eb2c2e9cf706dc985b1`,
and additive-catalog SHA-256
`9042968ead33dd098870d21582bc3114706d3af3841bdb3ab7a0d40c5727d990`.
The canonical report bytes have SHA-256
`3661d9fe60d78de51bf518fff32282b437b770515c7bbb9a1263072dfb0d13ac`.

An additive seventh tranche contributes 20 semantic specifications and 100
bundles for manifest-driven case routing and byte-exact batch transforms.
`case-routed-batch-transform` crosses source-suffix, record-kind, leading-byte,
and declared-action routing with skip, verbatim-copy, reject-batch,
default-route, and error-record fallback policies. Two separately structured
semantic constructions must agree before fixture admission. The checked-in
hash-only report is
[reports/executable-seventh-tranche/manifest.json](reports/executable-seventh-tranche/manifest.json),
with family task-set SHA-256
`e68a7e4614424e76fa35d4c0650e500469b971f1a5010d309115b0c225b7b2e6`,
added-registry SHA-256
`14aa05939c2ac2f4954196968003254dee39175f1d1d94e32213b8a74cfff19e`,
cumulative-suite SHA-256
`341b50a83305a9e0c64ada387eee461209ca75d1083e34fe2887a608179de131`,
and additive-catalog SHA-256
`99dcf8918151a5a87bdeea8f51bde8ad6e10063b46419a334d7d8b211310e6d8`.
The canonical 56,368-byte report has SHA-256
`49c17168813721bc9f66213f4e5b6dd873d97aadd0afd0839a3533a77f7251d9`.

An additive eighth tranche contributes 20 semantic specifications and 100
bundles for collision-safe batch rename planning and mutation-aware final-state
verification. `collision-safe-batch-rename` crosses ASCII-lowercase,
per-parent numbered-prefix, suffix-rewrite, and manifest-mapping rules with
reject-all, skip, stable-first, stable-last, and exact-byte-coalescing
policies. Two independently structured engines must agree on the source-action
plan, flat output tree, ledger, and representative metadata before fixture
admission. The checked-in hash-only report is
[reports/executable-eighth-tranche/manifest.json](reports/executable-eighth-tranche/manifest.json),
with family task-set SHA-256
`6c563074579359d666faaae2aebf69019c74521e8946cea6a2fe19a756c744cd`,
added-registry SHA-256
`8ef6879c5b6f4198c1b0ff2acfcffe89b6cbdd418a9aa2af2eefedfb12994736`,
cumulative-suite SHA-256
`b22742179e3ce3b7331469de9db0a75ddbae81a3340e2b814c8a7ab34233f0f0`,
and additive-catalog SHA-256
`05e4b90408a0970dfded597e5ee7813386bfdaed50a1cea301148eaabd83c297`.
The canonical
`56,369`-byte report has SHA-256
`822f2e20e5f73d638dff810c12aec0985145b642801975f6148b034ecf155d0e`.

The additive ninth tranche contributes 20
`hardlink-deduplicated-mirror` tasks and 100 topology-aware fixtures. Its
4-by-5 grid separates content equivalence from deterministic metadata-owner
selection; dedicated probes make all 20 cells oracle-distinct, and separate
materialization tests exercise real filesystem states.
Separately structured parsing and grouping paths must agree before shared
final-state assembly, and the final-state verifier checks exact bytes, modes,
mtimes, input preservation, link counts, and portable visible hardlink-group
identities. The added-registry SHA-256 is
`ff886754b054445a90ad30197d004e4071dba72bf0af17931d05e461c7e90703`,
the cumulative-suite SHA-256 is
`d0647e24f29abd59f8c2d6b2ac2a404aee78b92c780f8be4f9b16d200885843b`,
and the cumulative catalog SHA-256 is
`56932666f2641b5947e1801378b233dd5f37f568e4f2b4c6aa171bad115b09d8`.
The fixed reviewed Bash canary solves all 100 public fixtures with only the
declared external tools. The
[56,392-byte hash-only manifest](reports/executable-ninth-tranche/manifest.json)
has SHA-256
`8bb43dfa235261ab5e237b26a5384d767a02ad351a8b3311fc909ad860b70b6b`.
See
[the component guide](HARDLINK_EXPERIMENT_INFRASTRUCTURE.md) for the
observation and authority limits.

The additive tenth tranche contributes 20
`compressed-archive-roundtrip-verify` tasks and 100 fixtures. Its 4-by-5 grid
crosses gzip, bzip2, xz, and uncompressed ustar with archive-, member-,
round-trip-, mode-, and strict-evidence projections. Every policy still faces
the same semantic archive and reconstructed-tree checks. The verifier accepts
portable codec output only when it is one bounded complete stream, parses the
decompressed ustar without extracting it, checks normalized regular members,
and derives the closed report from the candidate's actual archive bytes. A
fixed reviewed Bash canary solves all 100 public fixtures with `PATH` limited
to the declared seven utilities. This is feasibility and verifier evidence,
not a candidate API, score, model-selection result, or research result. See
[the tenth-tranche component guide](ARCHIVE_ROUNDTRIP_EXPERIMENT_INFRASTRUCTURE.md)
for its exact observation limits. The task-set, added-registry,
cumulative-suite, cumulative-catalog, discrimination, and canonical
56,553-byte
[hash-only manifest](reports/executable-tenth-tranche/manifest.json) SHA-256
values are
`450ba507f0672e3a47ca6d495a6553d07294c605f94b3c5f03aa111d42bf771a`,
`0d07fd82de275ffd9dc274b97a6fa02fdd0620f83d5ee90a2bea0ad64f06f0ab`,
`629119116c53a0be2cc7cacb5461ae13de7d50f29b0a129707a840089ab48d2f`,
`5a29ea69111028fe69322d892e061a723ab53fb857ce4077cca924e314a4f4d6`,
`ae95eef5802c010e70e338d257f5d0f3d01a39fa5cf471f945a8b75f554faa21`,
and `02442d60bf7d7874016fc9d50857cd49f9d8e1342ece55a42d7c8afcd852f0fb`.

The additive eleventh tranche contributes 20 `checksum-repair-plan` tasks
and 100 fixtures. Four strict manifest encodings cross five declarative
repair policies. Two semantic derivations must agree on duplicate-preserving
record order, no-follow asset status, batch state, actions, and exact JSONL
meaning. A fixed reviewed Bash canary solves all 100 public fixtures with
`PATH` limited to the declared five utilities. See
[the eleventh-tranche component guide](CHECKSUM_REPAIR_EXPERIMENT_INFRASTRUCTURE.md)
for the contract and assurance limits. The task-set, added-registry,
cumulative-suite, cumulative-catalog, discrimination, and canonical
56,202-byte
[hash-only manifest](reports/executable-eleventh-tranche/manifest.json)
SHA-256 values are
`e52fb74ece2a94baa9bd1b2f6da25ca103839e1e9666361fe5406c34a36b9bb0`,
`bd0c14880eb25fa80100c317fa41086c45c59147407a67f03981831bcfdfc100`,
`f62ba1c1214fc48f194a5dea9c69c04962cc14dbdccfc38640cf4eee833018cb`,
`cd4221870ba4bfd5ade5098bddccc15af47865930bf173f05141194f3e0b8177`,
`f71ba70f0a4d004bed235e897a73c1222c6d2687e4eeb842c008f7878e9457aa`,
and `d6916730cd81170f067b0669812063fd4071102494fd56174b01672b5cad0d59`.

The additive twelfth tranche contributes 20
`jsonl-csv-enrichment-compose` tasks and 100 fixtures. Four strict mixed-codec
layouts cross five missing-field policies. Two semantic derivations must agree
on parsing, missing-ID nonjoinability, duplicate-key Cartesian multiplicity,
rejections, and ordered semantic JSONL. A fixed reviewed Bash canary solves
all 100 public fixtures with `PATH` limited to the declared four utilities.
See
[the twelfth-tranche component guide](JSONL_CSV_ENRICHMENT_EXPERIMENT_INFRASTRUCTURE.md)
for the contract and assurance limits. The task-set, added-registry,
cumulative-suite, cumulative-catalog, discrimination, and canonical
56,394-byte
[hash-only manifest](reports/executable-twelfth-tranche/manifest.json)
SHA-256 values are
`60a8ab6770bae6de43d430db9e3edf136f28f0a0ad2dacfd09b627ce19cf75c3`,
`a9733f220a7bdfb8435841eff875c9fd7b1dbadbee6de2d2aa0646750164f862`,
`32ec82cf193f364946def16462e52217176093d0a3f6399d574c9faf66eaa4a1`,
`98cf6ffa48cbe11ece96195450335e5be9a3d0898d54e91396d0c2756171f169`,
`732c1438a4337d2043ee85e2eb4e9e7c437a0051eb1a828cdac6139845db0e94`,
and `792bb1a4116d6698cc07cebfa6edef9c6358ccd4fe497d99703e88ed81262103`.

The additive thirteenth tranche contributes 20
`nested-json-schema-migration` tasks and 100 fixtures. Four bounded source
shapes cross five exact v1-to-v2 migration policies. Two derivations must agree
on strict decoding, policy semantics, map ordering, the numbered document set,
and its closed manifest. A fixed source-reviewed Bash wrapper invokes
`python3 -I -S` and solves all 100 public fixtures with `PATH` limited to
`mkdir`, `python3`, and `sort`. See
[the thirteenth-tranche component guide](NESTED_JSON_SCHEMA_MIGRATION_EXPERIMENT_INFRASTRUCTURE.md)
for the contract and assurance limits. The task-set, added-registry,
cumulative-suite, cumulative-catalog, discrimination, and canonical
56,396-byte
[hash-only manifest](reports/executable-thirteenth-tranche/manifest.json)
SHA-256 values are
`2ab692e66a3090b5d05a204b18f4fdb99ddc822cdbaa5b7912b7ac2166680e0b`,
`01990ca4355ef20736861d7bb7753e09e5ccbbfbddf8d21c4ffce3a451d83873`,
`bb7b78b68879eb32d4849bb5d82cac7a90b0695dc3fa72b9836dd7b6e70863e0`,
`25142ebdc014f4d4a53bba34bb9ffeaffa6f87789169180fe0caab69b02fcb9f`,
`416907543c373f36e55098c514fbe17aeef0192d9e5dc43cd025bed809a0ad42`,
and `0250c1e3134d342c57378f0fb8a3b6c4c06ae84ca4fdee4dcda743eefcff8fb7`.

Together the thirteen tranches provide 440 of the 500 required
method-development specifications and 2,200 concrete fixture bundles across
22 integrated families. They remain public, unsealed, unscored, and
nonauthorizing, and independent human review remains unattested. The remaining
60 specifications and the trusted sandbox/supervisor still block general
synthesized-candidate execution. The V1 `DevelopmentInvocation` below
deliberately admits only the
frozen first tranche; a cumulative invocation protocol has not been
authorized. Separately,
the generated 20,250-record
benchmark scaffold continues to carry only semantic graphs and fixture
descriptors; it does not materialize the complete sealed evaluation fixtures,
independent checkers, or execution traces.

The preserved, now-superseded
[configs/executable-method-development-coverage-v1.json](configs/executable-method-development-coverage-v1.json)
freezes the complete 25-family/500-task allocation: 17 integrated families
and 340 tasks plus 8 planned families and 160 tasks. It fixes each family's
two-axis 4-by-5 task grid, solution track, tool set, filesystem schema, output
contract, and capability tags. Its semantic coverage SHA-256 is
`6c215d9eaf5581aaa146d6814a9d40621a57459c5af98ae4ca625caff10c9c8c`,
and the canonical config bytes have SHA-256
`46f98f54ef5682ce0adc3854557ecfe8ed092fd5e916935bc27702edb4e86efa`.
It remains immutable historical planning evidence. Implementation review found
that its planned hardlink grid contained redundant, nondeterministic, and
nonorthogonal cells. The backward-linked
[v2 coverage lock](configs/executable-method-development-coverage-v2.json)
promotes the fully discriminable hardlink grid and now binds 18 integrated
families/360 tasks plus 7 planned families/140 tasks. Its semantic coverage
SHA-256 is
`7406480a1dc06bc99d1e36fde1a328a490d6cc8d6b96ee38c924a902acbf9abd`.
The separate
[migration record](configs/executable-method-development-coverage-v1-to-v2-migration.json)
proves that exactly one family declaration changed. Neither record grants
implementation sealing, review, scoring, execution, model-selection, or claim
authority. Coverage v2 remains immutable historical evidence. The
[v3 coverage lock](configs/executable-method-development-coverage-v3.json)
preserves its exact bytes, promotes only
`compressed-archive-roundtrip-verify`, and binds 19 integrated families/380
tasks plus 6 planned families/120 tasks. Its semantic SHA-256 is
`b37f48c98e7216c78ddf74d0ce6f6d74cd095575f20f53de6bf30018b2180d79`,
and its 23,943 canonical bytes have SHA-256
`de241ad1e4536fa595f99acf0ef05a3e423418876298c576abe87249c018bc0a`.
The
[v2-to-v3 migration record](configs/executable-method-development-coverage-v2-to-v3-migration.json)
proves the other 24 family records are unchanged. Its semantic SHA-256 is
`8e36252576376d86ddb0a4f3b399dfdd66377b0ed026369bbf799edf104818a2`;
its 4,358 canonical bytes have SHA-256
`77820327bc105d367d8d737c110e53e8183ce786650ecb4c1699991412cb6683`.
Coverage v3 remains immutable historical evidence. The backward-linked
[v4 coverage lock](configs/executable-method-development-coverage-v4.json)
promotes only `checksum-repair-plan` and binds 20 integrated families/400
tasks plus 5 planned families/100 tasks. Its semantic SHA-256 is
`1bd7a4b6ab721404f1d1eb7a64718ba7df783998bf16cd603afb86eb2420d67c`;
its 24,590 canonical bytes have SHA-256
`d003a5748da855257aa93e0c6e1b7a4be2de393ec5faa0dcb32d74156f40b3d7`.
The
[v3-to-v4 migration record](configs/executable-method-development-coverage-v3-to-v4-migration.json)
proves the other 24 family records unchanged. Its semantic SHA-256 is
`667e31ef974829a5114544b1f1164f25c0f7515f67ef5600c979e85a3bcc3d8b`;
its 4,701 canonical bytes have SHA-256
`a1a783544d76f471688afe5f45eaf0f16c30a6ce04c36d1d5a438d6c8e439b7f`.
The historical backward-linked
[v5 coverage lock](configs/executable-method-development-coverage-v5.json)
promotes only `jsonl-csv-enrichment-compose` and binds 21 integrated
families/420 tasks plus 4 planned families/80 tasks. Its semantic SHA-256 is
`e5987525654e384c2696908bf147e8224ad3bdc1fb2e0bbc3856a4f23cdca8b9`;
its 25,241 canonical bytes have SHA-256
`cfb91bef706fc1c4fd4f95d7891f42e3ec058bbaba28997a22a0f72614d6268f`.
The
[v4-to-v5 migration record](configs/executable-method-development-coverage-v4-to-v5-migration.json)
preserves the first two promotion records and proves the other 24 family
records unchanged. Its semantic SHA-256 is
`7119bbf14ae74047a555483fc7e6e3a9d74ce46cdcb741a13aa5da34a66e1cea`;
its 5,052 canonical bytes have SHA-256
`f1d4566d17c7b51b3649000f896272ca56ec2f6d32fe5563aa4751c4a6fa563f`.
The current backward-linked
[v6 coverage lock](configs/executable-method-development-coverage-v6.json)
preserves exact v5 bytes, promotes only `nested-json-schema-migration`, and
binds 22 integrated families/440 tasks plus 3 planned families/60 tasks. Its
semantic SHA-256 is
`044f026b67a531613b1034b27056f1b6f91e1d95ae8902108428e67a6a9c31cf`;
its 25,899 canonical bytes have SHA-256
`e526485ba7b34c0325ff6809dcee428c251cd25dd34e907ca3b2eff56c174d68`.
The
[v5-to-v6 migration record](configs/executable-method-development-coverage-v5-to-v6-migration.json)
preserves the first three promotion records and proves the other 24 family
records unchanged. Its semantic/config-byte SHA-256 values are
`5c345bc6860f5c9ff70dba656d3cc1204acb705a0d2c4526b4031364313d7e90`
and `31f99bd95165b44cdd5aa4d9bc668b1fcf559a1d621a56c14c80a8d1c5521a8e`
for 5,423 canonical bytes. The next planned family is
`dependency-dag-execution-plan`.

`src/cbds/executable_compound_path_query.py` supplies 20 of the additive third-
tranche tasks and five deterministic profiles per task (100 fixtures). Two
structurally independent production oracles must agree, and a pinned-workspace
property verifier checks authenticated inputs, complete output state,
no-follow reads, final rescans, and workspace mutations in normal and optimized
modes. Sequential scans still require a trusted supervisor to hold the
workspace quiescent, and the family has not completed independent human
production review. It is admitted only through the third-tranche exact local
types and remains outside `DevelopmentInvocation`. Its fixture model
represents file and symlink leaves but not explicit directory modes, so it does
not cover directory permission errors.

`src/cbds/executable_log_aggregation_pipeline.py` supplies the other 20 tasks
and 100 fixtures over recursive no-follow log discovery, strict byte-level TSV
parsing, ERE filtering, malformed-row policies, grouped count/sum aggregation,
and raw-byte ordering. Its two independently structured production oracles
must agree. A local property verifier authenticates the task/profile/bundle
and pinned workspace, requires exact input preservation, enforces the complete
output mode/link/size/tree policy, reads through bounded descriptor-relative
egress, and repeats the scans after reading. Directory permission and
effective-access failures remain explicitly outside its fixture coverage. It
is public, unsealed, unscored, and nonauthorizing. The third-tranche catalog
admits it through exact family-local types, but V1 invocation support remains
absent.

`src/cbds/executable_ustar_pack.py` supplies the 20 fourth-tranche tasks and
five deterministic profiles per task. It creates only regular POSIX-ustar
members, orders names by UTF-8 bytes, fixes ownership and time metadata, and
checks exact archive and final-workspace semantics with separately structured
constructions. The verifier requires a quiescent workspace supplied by a
trusted supervisor; final-state inspection cannot prove transient `chmod`,
symlink-follow, or tool-invocation history. The fixture model also does not
exercise explicit directory permission failures or live effective-access
decisions. It remains outside V1 invocation and grants no candidate-execution,
model-selection, scoring, or claim authority.

`src/cbds/executable_pipefail_atomic_report.py` supplies the 20 fifth-tranche
tasks and five deterministic profiles per task. Logical stage statuses are
fixture data, and the semantic constructions consume complete streams before
applying those statuses, so the expected aggregate does not depend on SIGPIPE
or short-circuit timing. The verifier checks the exact final report or required
absence, source preservation, output modes and links, and the complete final
tree. Although the task contract requires sibling-file atomic rename and full
pipeline status capture, a final-state verifier cannot observe atomic-rename
history, Bash `PIPESTATUS`, executed pipeline topology, or tool-invocation
history. It therefore requires trusted supervisor-established quiescence and
does not claim global quiescence, directory-permission-error coverage, or live
effective-access coverage. The family remains outside V1 invocation and grants
no candidate-execution, model-selection, scoring, or claim authority.

`src/cbds/executable_bounded_retry_state_machine.py` supplies the 20 sixth-
tranche tasks and five deterministic profiles per task. Its immutable event
ledger distinguishes success, transient failure, ordinary failure, and
terminal failure; total-attempt limits and retry eligibility make all five
policies behaviorally distinct. The trusted semantics bind exact attempt and
terminal reports for linear, branching, bounded-cyclic, and compensating
models, including per-state-visit budget resets, empty ledgers, missing events,
cycle limits, and compensation causes. The final-state verifier checks both
reports, exact input preservation, modes, links, and the complete tree. It
cannot observe whether a candidate actually retried, waited, traversed the
reported transitions, performed compensation, used the allowed tools, or
published atomically; nor can it prove global quiescence, transient input
preservation, or candidate exit status. A trusted supervisor must establish
quiescence. Directory-permission and live effective-access failures remain
uncovered. The family is public, unsealed, unscored, nonauthorizing, outside V1
invocation, and has no independent human-review attestation.

`src/cbds/executable_case_routed_batch_transform.py` supplies the 20 seventh-
tranche tasks and five deterministic profiles per task. It reads a manifest,
classifies each logical record by exactly one configured signal, applies the
corresponding byte transform, and resolves unmatched records under one of five
batch-level fallback policies. Independent parsers, routers, transforms, and
serializers must agree. The descriptor-relative verifier checks authenticated
inputs, exact output bytes, modes, links, and the complete final tree. It
requires supervisor-established quiescence and cannot observe route,
transform, read-scope, tool, or atomic-publication history, candidate exit
status, directory-permission failures, live effective-access failures, or
global quiescence. A fixed, source-reviewed Bash canary passes all 100 public
fixtures with `PATH` limited to `awk`, `mkdir`, `sed`, `sort`, and `tr`, and a
separate binary case covers NULs, invalid UTF-8, and missing final newlines.
That canary runs one hand-authored program: it is not a caller-selected
candidate API, production sandbox, scored evaluation, model-selection result,
or research claim. The family remains public, unsealed, unscored,
nonauthorizing, outside V1 invocation, and without independent human review.

`src/cbds/executable_collision_safe_batch_rename.py` supplies the 20 eighth-
tranche tasks and five deterministic profiles per task. It flattens recursively
discovered regular candidates under four rename rules, then applies one of five
collision policies. The oracle commits an immutable per-source action plan as
well as the exact ledger and output files. Its mutation-aware verifier requires
removed sources to be absent, retained leaves to match their authenticated
baseline, original directories to retain kind/mode/link topology, and each
published file to preserve the selected representative's bytes, mode, size,
and modification time. Independent dictionary/group and sorted-stream engines
must agree before admission. A fixed source-reviewed Bash canary realizes all
20 rule/policy cells on the binary profile under a restricted `PATH`; a
separate equality probe covers every byte value plus leading, consecutive, and
trailing NUL boundaries. These are engineering-feasibility checks, not a
caller-selected candidate API, production sandbox, scored evaluation,
model-selection result, or research claim. Final-state scans cannot prove
actual rename or inode identity, collision-decision or read scope, allowed-tool
use, staging or atomic-publication history, crash rollback, transient input
preservation, global quiescence, or candidate exit status. The family remains
public, unsealed, unscored, nonauthorizing, outside first-tranche-only V1
invocation, and without independent human review.

`src/cbds/development_invocation.py` admits the frozen first-tranche catalog
through its registry, suite, and catalog digests, then binds each request to
one selected task, profile, and fixture bundle. Its canonical framed request
contains the original model response, the Bash program reproduced by the
frozen response parser, and the answer-free fixture inputs and output policy;
it contains no trusted-oracle answer bytes. Repeated requests may use a typed
catalog admission created by one exhaustive catalog validation, while every
invocation still revalidates the admitted catalog shell and selected objects.
The typed admission and `DevelopmentInvocation` are private trusted-controller
handles that transitively retain the catalog's oracle bytes; they must never
cross into a candidate process. Only their framed request and hash-only audit
projections are answer-free boundary objects.
The reverse protocol admits only a content-bound blocked result. The executor
accepts only an exact validated `DevelopmentInvocation`, produces a reviewable
launch plan with hard blockers including unpinned host `/usr`, and always
raises before launching a candidate.

`src/cbds/development_reviewed_bash_fixture.py` narrows the next integration
step to one exact public-development case. It exhaustively admits the frozen
first catalog, selects the `spaces-unicode` fixture for one path-suffix
inventory task, binds a fixed fenced Bash response through the existing parser
and invocation protocol, and authenticates before descriptor-relative
materialization. The reviewed program uses Bash builtins plus only the task's
declared `find`, `mkdir`, and `sort` tools. The private case retains trusted
objects; its public projection contains answer-free audit metadata. It does not
execute the program, verify a post-execution workspace, or authorize candidate
execution, scoring, model selection, or a claim.

`src/cbds/development_reviewed_bash_canary.py` consumes only that fixed case;
its public execution entry point accepts only an optional nonce and no caller-
selected program, command, fixture, runtime, or verifier. The controller
rebuilds and pins the checked-in native supervisor, transfers sealed program
and runtime payloads through systemd service descriptors, reconstructs a
read-only root in Bubblewrap, and runs the reviewed Bash program under native
PID1 supervision. After the transient cgroup is inactive and empty, it seals
and parses the supervisor's bounded workspace projection, revalidates the
descriptor-pinned input baseline, compares the output-side tree, and invokes
the trusted fixture verifier. The resulting evidence is permanently
nonauthorizing and does not represent a model candidate or a score.

`src/cbds/development_candidate_protocol.py` fixes the binary transport
contract used by that reviewed canary: a 384-byte request binds the nonce,
invocation, program, fixture definition, initial workspace, runtime snapshot,
allowed tools, policy, and resource ceilings; the protocol version separately
fixes descriptors 3, 4, and 5 as the program, fixture identity, and workspace
snapshot sink. A
512-byte result repeats those identities and binds process status, classified
outcome, cap-plus-one stream observations, separate cumulative `wait4`
user/system totals, and a cumulative CPU maximum that also incorporates live
namespace-tree observations used for enforcement, plus descendant reaping,
wall time, and an output-side workspace snapshot. Strict
parsing and mutation tests cover the request/result relationship. The protocol
module itself has no launch API, and every canonical authority field is
permanently false.

The snapshot audit projection is only digest-bearing and raw-payload-byte-
free. It still exposes paths, modes, sizes, and payload digests, so it is not
answer-confidential and must not be reused across a sealed-evaluation boundary
or returned as benchmark feedback.

`src/cbds/development_runtime_bundle.py` builds a source-closure manifest for
explicitly named ELF executables. It records the `PT_INTERP`/`DT_NEEDED`
closure, ordered library searches and negative lookups, and declared usr-merge
aliases under pinned roots. Aggregate-payload and entry ceilings plus strict
source replay and path-race checks bound that inspection. The separate runtime
materializer requires a trusted expected manifest digest, copies the validated
projection into a newly created descriptor-relative no-follow destination,
normalizes regular-file modes to the source execute/read bits with all write
and privilege bits removed, seals directories to mode `0555`, replays the
source before and after copying, and records two agreeing final scans.

That materialization evidence is non-authorizing. Live binding replays the
trusted source and rescans the named destination, but proves only a
point-in-time match. `src/cbds/development_runtime_fd_snapshot.py` closes the
regular-payload portion of that race: it pins and rescans the full projection,
copies authenticated regular bytes into content-sealed CLOEXEC memfds, and
returns independent-offset read-only descriptors while serializing no FD
numbers. A frozen, hash-checked helper canary separately proves CLOEXEC absence
and an exact, exclusive explicit-`pass_fds` subprocess handoff while executing
through the already-open, content-hashed interpreter FD. The interpreter does
not yet have an external trust anchor, so the evidence does not call that child
harmless.

`src/cbds/development_runtime_namespace_canary.py` now constructs a narrower,
candidate-input-free namespace-transfer request for one fixed snapshot-bound
`/usr/bin/busybox` payload. It admits exactly `/`, `/usr`, and `/usr/bin`, one
regular payload, and no symlinks or extra runtime files. User-systemd
`OpenFile=` is asked to hand its sealed descriptor to Bubblewrap
`--ro-bind-data`; the command applies the recorded mode and performs a final
read-only root remount without reopening a mutable runtime source path. The
built-in real runner bounds wall time and each captured stream, applies fixed
cleanup, requests systemd memory, PID, open-file, CPU-quota, and runtime
ceilings, and accepts only the hash-bound probe input and exact response frame.

This canary exposes no synthesized-candidate, command, fixture, verifier, or
score input parameter, but its sole snapshot payload is still executable
program bytes. Local hashes do not establish external trust or harmlessness
for systemd/Bubblewrap/systemctl or the purported BusyBox payload. Payload/root mutation resistance,
descriptor closure, workspace/network/host-path isolation, the two handoffs,
projected payload/mode, and probe execution are consequently untrusted
self-reports, not verified security facts. It also does not establish the
Bash runtime-data/`dlopen` closure, a trusted supervisor/PID1, child seccomp,
a cumulative CPU watcher, candidate output-overflow classification,
descendant quiescence, exact-tool policy, or any candidate/scored/claim
authority. The generic candidate executor remains unconditionally blocked.

`native/cbds-development-supervisor.c` and
`src/cbds/development_supervisor_canary.py` add a narrower native lifecycle
proof. The Python controller compiles the pinned descriptor for one checked-in
static-PIE source,
requires byte agreement with a caller-pinned binary, seals it behind a file
descriptor, and launches it as PID1 in a fresh rootless Bubblewrap namespace
inside a user-systemd cgroup envelope. An exact authenticated binary protocol
admits only nine fixed scenario IDs: normal, real double-fork/`setsid`, zombie,
wall timeout, stdout overflow, stderr overflow, CPU fan-out, forbidden syscall,
and result-frame spoof. The C supervisor installs child-only `no_new_privs`,
non-dumpability, and a fixed raw-BPF seccomp filter, captures cap-plus-one
streams, kills and reaps the namespace process set with `wait4` accounting,
checks that only PID1 remains, and returns a request-bound result frame. Both
normal and abnormal controller paths then require the transient unit to report
inactive/dead with no control-group path and synchronously reap the wrapper.

The live development-host suite passes, but this is deliberately not a generic
supervisor. It accepts no candidate, command, fixture, workspace, or verifier;
the fixed child filter is not a Bash policy; summed CPU is measured but not
limited; and local source/compiler/launcher hashes are not external trust
anchors. General supervisor, seccomp, CPU, tool-policy, candidate execution,
scoring, model-selection, and claim fields therefore remain false.

BashBench release v1 is also diagnostic-only. A non-executing audit of its
released source and data did not establish candidate handoff from the general
harness into the tests, found inconsistent evaluation/test task identities and
counts, and found direct host-temporary-directory execution without a sandbox
boundary. It cannot serve as independent confirmation unless an audited port
adds explicit handoff and task binding, independent verifier mutation
evidence, and the pinned sandbox/resource controls required by
[PLAN.md](PLAN.md).

The three preregistered dense backbones have been downloaded locally and
passed static inspection, CUDA loading, a finite-forward check, and
seeded-input synthetic micro-training fit probes. CUDA optimization is not
claimed to be bitwise reproducible. No terminal behavior or
capability score has been measured, so no backbone has been selected. The
versioned pilot report therefore has `claim_scope: none` and
`selection_authorized: false`; no experimental result is claimed in this
repository.

The pinned NL2SH-ALFA training import has also been reproduced into a
content-addressed two-partition logical corpus, and a Qwen3 tokenizer schedule
has been reconstructed to exact token and pack hashes. Authentication means
only that the bytes and deterministic transformation match their pins. The raw
target is a mixture with unresolved row-level lineage, placeholders,
out-of-policy utilities, and no execution oracle; it is not accepted training
data. The versioned data-pilot report therefore has `claim_scope: none` and
forbids model selection or research training.
The authenticated lexical audit rejects 35,785/40,533 rows and identifies 681
normalized-prompt collision groups covering 2,326 rows. Because Bash parsing,
fixture execution, policy admission, row-level license resolution, and all
evaluation-overlap bindings remain absent, the 4,748 lexical survivors cannot
feed a campaign run.

The real-text dense canary consumed the exact 1.6M/0.4M target/support
engineering schedule in 251 updates, exported the same 596,049,920-parameter
dense architecture, and passed independent serialized-file, logical-tensor,
model-inspection, source-pin, and ledger-chain verification. Its 149.24-second
training time and memory/throughput figures are descriptive host diagnostics;
the checked-in report forbids model selection and research claims.

The dependency-free local inspector validates Safetensors storage and reports
conservative dense/MoE evidence, stored tensor elements, component bytes, and
domain-separated artifact identities. The optional runtime probe adds exact
physical/trainable storage accounting and one local causal-LM forward
qualification. The exact dense qualifier now proves static checkpoint
completeness for the supported Qwen2, Qwen3, and Llama contracts, and the
prospective binder applies model-derived index, factorization, pruning-count,
tokenizer, and quantization lower-bound checks. Neither establishes runtime
parameter-graph equivalence or model quality. A separate completed-model
companion now freshly reopens supported floating-dense source/export artifacts
and passively validates saved runtime reports, but it remains nonauthorizing
and does not prove exact selected-unit/value provenance or training-source
consumption. Supplying `--experiment-manifest` to evaluation-spec validation
exactly binds the completed export and report digest, but still does not open
the report or independently verify its claims.
