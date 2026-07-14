# Capability-Budgeted Dense Specialization

Research workspace for improving Unix-terminal performance per unit of model
capacity in dense language models with fewer than one billion parameters.

The project compares fixed-size post-training with task-aware structural and
deployment compression. It does not treat safety-oriented suppression or
ability loss as a result unless target performance or deployed footprint
improves.

- [Research plan](PLAN.md)
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
Safetensors inspection, sandbox command construction and read-only runtime
preflight, prospective run and scored-evaluation specifications,
completed-record accounting, completed-export evaluation/hardware binding,
cross-document task-result binding, campaign-wide replicate/evaluation
binding, paired confirmatory statistics, collection-derived outcome binding,
fail-closed claim-policy evaluation, and four public-development static
fixture/verifier families are implemented. Evaluation specs validate and hash
prospective contracts; they do not open benchmark assets or execute
candidates. The development fixtures are test assets, not sealed evaluation
data. A bounded public-development namespace/cgroup preflight and candidate
launch-plan builder are implemented, but candidate execution remains
unconditionally blocked until the trusted supervisor, child seccomp, CPU-time
watcher, bounded capture, quiescence, and exact-tool-policy gates exist.
Complete semantic-family coverage, claim-eligible curated data, research
training runs, and research results are not yet present. A 2M-visible-token
Qwen3 dense-SFT canary has completed solely to qualify the training/export
plumbing; it is not a backbone score or campaign run.

The four public-development verifier families are a narrow executable-fixture
exception to the bulk semantic scaffold: their trusted APIs materialize
deterministic filesystem fixtures through pinned, no-follow directory
descriptors and verify post-execution state, but never invoke candidate code.
The generated 20,250-record benchmark scaffold still carries only semantic
graphs and fixture descriptors; it does not materialize the complete sealed
evaluation fixtures, independent checkers, or execution traces.

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
qualification, but it does not prove checkpoint completeness or model quality.
Manifest binding does not yet open or validate those inspection and runtime
reports. Supplying `--experiment-manifest` to evaluation-spec validation
exactly binds the completed export and report digest, but still does not open
the report or independently verify its claims.
