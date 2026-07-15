# Capability-Budgeted Dense Specialization

Research workspace for improving Unix-terminal performance per unit of model
capacity in dense language models with fewer than one billion parameters.

The project compares fixed-size post-training with task-aware structural and
deployment compression. It does not treat safety-oriented suppression or
ability loss as a result unless target performance or deployed footprint
improves.

- [Research plan](PLAN.md)
- [Experiment components and their roles](EXPERIMENT_COMPONENTS.md)
- [Experiment infrastructure guide](EXPERIMENT_INFRASTRUCTURE.md)
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
fail-closed claim-policy evaluation, and ten cataloged public-development
static fixture/verifier families are implemented. Two separate 20-task
families—`compound-path-query` and `regex-log-group-aggregation`—with 200
fixtures total are staged locally but are not part of those closed catalogs or
their invocation protocol. A catalog-admitted
development invocation protocol, bounded runtime-bundle materializer, sealed regular-
payload snapshot, fixed-protocol descriptor-handoff canary, and candidate-input-free
fixed-BusyBox namespace-transfer canary are also implemented. A separate
candidate-input-free native PID1 lifecycle canary covers nine fixed fork,
timeout, output, CPU, seccomp, and spoof scenarios. One frozen first-catalog
fixture and reviewed Bash response are now bound into a private, nonexecuting
integration case, and a separate fixed binary protocol binds the identities
and limits a future native candidate supervisor must consume and return. None
is a candidate execution path. Evaluation specs validate and
hash prospective contracts; they do not open benchmark assets or execute
candidates. The development fixtures are test assets, not sealed evaluation
data. A bounded public-development namespace/cgroup preflight and
catalog-bound candidate launch-plan builder are implemented, but candidate
execution remains unconditionally blocked until the externally trusted Bash
runtime closure and candidate supervisor integrate a Bash-specific seccomp
policy, cumulative CPU enforcement, workspace quiescence, exact-tool policy,
and scored outcome binding.
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

Together the two tranches provide 200 of the 500 required
method-development specifications and 1,000 concrete fixture bundles. They
remain public, unsealed, and unscored. The remaining 300 specifications and
the trusted sandbox/supervisor still block candidate execution. The V1
`DevelopmentInvocation` below deliberately admits only the frozen first
tranche; a cumulative invocation protocol has not been authorized. Separately,
the generated 20,250-record
benchmark scaffold continues to carry only semantic graphs and fixture
descriptors; it does not materialize the complete sealed evaluation fixtures,
independent checkers, or execution traces.

`src/cbds/executable_compound_path_query.py` separately stages 20 additional
public-development tasks and five deterministic profiles per task (100
fixtures). Two structurally independent production oracles must agree, and a
pinned-workspace property verifier checks authenticated inputs, complete output
state, no-follow reads, final rescans, and 15 workspace mutations in normal and
optimized modes. Sequential scans still require a trusted supervisor to hold
the workspace quiescent, and the family has not completed independent human
production review. The family is absent from the
closed first/second registries and catalogs, the cumulative 200-task/1,000-
fixture identities, and `DevelopmentInvocation`; those counts therefore do
not change. Its fixture model represents file and symlink leaves but not
explicit directory modes, so it does not cover directory permission errors.

`src/cbds/executable_log_aggregation_pipeline.py` stages another 20 tasks and
100 fixtures over recursive no-follow log discovery, strict byte-level TSV
parsing, ERE filtering, malformed-row policies, grouped count/sum aggregation,
and raw-byte ordering. Its two independently structured production oracles
must agree. A local property verifier authenticates the task/profile/bundle
and pinned workspace, requires exact input preservation, enforces the complete
output mode/link/size/tree policy, reads through bounded descriptor-relative
egress, and repeats the scans after reading. Directory permission and
effective-access failures remain explicitly outside its fixture coverage. It
is public, unsealed, unscored, nonauthorizing, and absent from the frozen
catalogs and invocation dispatcher. The staged total is therefore 40 tasks and
200 fixtures; the frozen cumulative identity remains 200 tasks/1,000 fixtures.

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

`src/cbds/development_candidate_protocol.py` separately fixes the binary
transport contract for that future canary: a 384-byte request binds the nonce,
invocation, program, fixture definition, initial workspace, runtime snapshot,
allowed tools, policy, and resource ceilings; the protocol version separately
fixes the descriptor roles. A
512-byte result repeats those identities and binds process status, classified
outcome, cap-plus-one stream observations, cumulative `wait4` CPU accounting,
descendant reaping, wall time, and a workspace snapshot. Strict parsing and
mutation tests cover the request/result relationship, but the module has no
launch API and every canonical authority field is permanently false.

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
qualification, but it does not prove checkpoint completeness or model quality.
Manifest binding does not yet open or validate those inspection and runtime
reports. Supplying `--experiment-manifest` to evaluation-spec validation
exactly binds the completed export and report digest, but still does not open
the report or independently verify its claims.
