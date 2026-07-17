# Rolling branch reviews

## Purpose

This is the decision log between infrastructure and experimental branches.
The presence of a plan item does not authorize automatically completing the
next item. Each branch ends with an evidence review and exactly one terminal
decision before downstream work begins:

- `continue`: keep the same branch open for evidence already in scope;
- `modify`: change the branch design, regenerate every affected identity, and
  review the modified branch again;
- `merge`: accept the branch into the main evidence chain;
- `stop`: terminate the branch without substituting a more favorable branch.

A branch still executing checks is marked `review in progress`; that is not a
decision and does not permit downstream work.

## Required review record

Every review records:

1. branch ID, scope, question, and predecessor;
2. preregistered acceptance criteria or diagnostic purpose;
3. exact artifacts, hashes, task/fixture counts, seeds, and software/runtime
   boundary;
4. observed results, uncertainty, failures, deviations, and compute cost;
5. claim boundary and unresolved risks;
6. one decision from the four values above, its rationale, and the next
   authorized action.

Hash publication is serialized. Independent read-only checks, fixture cells,
seeds, and experimental arms should use up to eight CPU cores when they have
isolated temporary/output state. The review records the actual allocation.
Shared-manifest publication, hash freezing, and stateful workspace tests are
always serialized. GPU training and latency measurements also remain
serialized whenever contention could alter the endpoint.

## Remaining major gates

| Gate | Branch boundary | Entry condition | Review question |
|---|---|---|---|
| 1 | Finish `symlink-aware-tree-reconcile` and independently review all 500 public-development tasks | Coverage v8/fifteenth branch receives `merge` | Is the complete development instrument coherent enough to seal, or must a family/verifier be modified or stopped? |
| 2 | Close and externally review the Bash runtime, tool, namespace, supervisor, quiescence, and target-hardware boundary | Gate 1 receives `merge` | Does the boundary safely and deterministically admit a general candidate, or should it be modified/stopped? |
| 3 | Build, human-audit, and freeze sealed static ID/OOD and bounded-interactive suites plus parser/rerun/exclusion/analysis policy | Gate 2 receives `merge` | Are the hidden instruments valid and sufficiently isolated to freeze? |
| 4 | Admit training data with lineage, licensing, AST/execution checks, ambiguity repair, balancing, and decontamination against the frozen suites | Gate 3 receives `merge` | Is any corpus claim-eligible, and which strata should merge, be modified, or stop? |
| 5 | Complete exporter-specific realization, runtime evidence, the production-training backend, executed-FLOP accounting, quantization calibration, and hardware reopening | Gate 4 receives `merge` | Are operator outputs and deployed costs measured exactly enough for behavioral screening? |
| 6 | Run backbone feasibility, capability support/transfer, and matched-compute operator branches, then fresh confirmation and one sealed opening | Gate 5 receives `merge` | After each model/operator branch, should it continue, modify, merge into confirmation, or stop? |

## Review: `infra-015-process-lifecycle-v8`

- Status: `complete`.
- Scope: the fifteenth public-development family
  `process-lifecycle-delta`, its 20 tasks and 100 fixture bundles, append-only
  registry/catalog/report, and the v7-to-v8 coverage promotion.
- Predecessor: Git commit `199eba7` and its frozen coverage-v7 artifact.
- Question: does the branch add a discriminable, independently derived,
  Bash-feasible static process-lifecycle family without widening candidate,
  scoring, model-selection, or claim authority?
- Acceptance evidence:
  - all exact semantic and file identities for this branch are published as
    distinct entries in the
    [artifact identity ledger](ARTIFACT_IDENTITY_LEDGER.md#fifteenth-tranche-and-coverage-v8);
  - core, Bash canary, registry, catalog/report, and coverage suites passed
    separately in normal and optimized Python;
  - schema/config validation, both deterministic builders, and an
    outside-checkout Python 3.12 wheel smoke passed;
  - the final combined normal gate passed 87/87 tests in 962.985 seconds;
  - the final combined optimized gate passed 87/87 tests in 965.597 seconds;
    neither gate reported a failure, error, skip, timeout, warning, OOM, or
    other resource anomaly.
- Commands: the seven modules
  `tests.test_executable_fourteenth_predecessor_evidence`,
  `tests.test_executable_process_lifecycle_delta`,
  `tests.test_executable_process_lifecycle_delta_bash_canary`,
  `tests.test_executable_static_fifteenth_registry`,
  `tests.test_executable_fixture_fifteenth_catalog`,
  `tests.test_executable_fixture_fifteenth_catalog_report`, and
  `tests.test_executable_development_coverage_v8` were passed in that order to
  `PYTHONPATH=src python3 -m unittest -v` and
  `PYTHONPATH=src python3 -O -m unittest -v`.
- Seed and runtime: the sole randomized differential audit used the frozen
  seed `0x51A7E`; training/model seeds are not applicable. Both final gates
  used CPython 3.14.4 built with GCC 15.2.0 on Linux
  7.0.0-27-generic x86_64. The public Bash canary observed GNU Bash 5.3.9,
  mawk 1.3.4-20260129, jq 1.8.1, and uutils `comm`/`mkdir`/`sort` 0.8.0.
  Those ambient utility versions are recorded diagnostics, not a claim-run
  runtime pin.
- Deviations and fixes during review: premature hash publication was blocked;
  reference-parser independence, integer lexical bounds, all-profile
  discrimination, fixture obligations, output-bound witnesses, hardlink
  domain parity, and prospective documentation were corrected before the
  frozen chain was accepted.
- Claim boundary: public, unsealed, unscored, nonauthorizing static synthetic
  evidence only; ambient public-canary utility versions are not a claim-run
  runtime pin.
- Parallel allocation: two independent CPU workers ran the normal and
  optimized final integration gates concurrently; lightweight
  static/schema/package checks used isolated processes. This branch did not
  expose eight conflict-free heavy partitions, so it stayed below the
  eight-core ceiling. The two final gates consumed 1,928.582 measured
  process-seconds; their concurrent critical path was 965.597 seconds plus
  launch overhead. The shared hash chain was frozen serially.
- Decision: `merge`.
- Rationale: every preregistered infrastructure acceptance check passed in
  both interpreter modes; identities and authority boundaries remained
  closed; the independent audit found no code, artifact, packaging, schema,
  or documentation blocker.
- Next authorized action: design Gate 1 and review that design before
  implementing `symlink-aware-tree-reconcile`. Gate 1 is not implemented by
  this decision.
