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

## Review: `infra-016a-symlink-lock-audit`

- Status: `complete`.
- Scope: read-only audit of the sole planned coverage-v8 family before any
  task, fixture, or publication implementation.
- Predecessor: Git commit `0d0fbf4` and its `coverage v8` artifact.
- Question: is the planned `symlink-aware-tree-reconcile` record sufficiently
  specified and tool-complete to implement unchanged?
- Evidence: the audit reopened the central family declaration, coverage-v8
  admission rules, generic workspace and fixture contracts, relevant
  hardlink/rename/path-query families, and the remaining-gate documents.
  Three independent reviewers and the root review agreed on the material
  findings.
- Findings:
  - the 4×5 axes, Bash-native track, identities, tags, and 20-task allocation
    are coherent;
  - none of the five policies, four codec grammars, safe-link equivalence, or
    operation-log semantics was defined;
  - the planned tool set cannot robustly parse JSONL/CSV or compare and copy
    arbitrary regular-file bytes;
  - generic bundle verification intentionally rejects expected symlink
    outputs, so the family needs an additive custom bundle/verifier;
  - output final-state evidence cannot prove in-place mutation or operation
    history.
- Runtime, seeds, and cost: this was a read-only source/design audit on the
  CPython 3.14.4/Linux 7.0.0-27-generic environment recorded by the predecessor
  review. No randomized, training, or model seed applies. Four concurrent
  reviewers used isolated reads; no shared artifact or hash was published.
- Claim boundary: design diagnosis only; no task behavior, candidate
  feasibility, 500-task review, score, or model result.
- Decision: `modify`.
- Rationale: implementing the planned record unchanged would force brittle
  bespoke parsers or silently narrow regular files to trivial payloads and
  would leave the policy axis underdetermined.
- Next authorized action: draft and adversarially review a corrected design
  while preserving the axes and scope. Do not implement or freeze family
  identities until the revised design receives its own decision.

## Review: `infra-016b-symlink-revised-design`

- Status: `complete`.
- Scope: revision 1 of the corrected prospective contract in
  [SYMLINK_TREE_RECONCILE_DESIGN.md](SYMLINK_TREE_RECONCILE_DESIGN.md)
  (commit `ddb90af`).
- Predecessor: the `infra-016a` `modify` decision.
- Question: does the revised copy-on-write design close the codec, policy,
  safe-link, verifier, resource, and feasibility ambiguities without widening
  the research claim?
- Acceptance criteria:
  - retain the frozen 4×5 axes and all non-tool allocation fields;
  - expose any tool-budget correction explicitly;
  - distinguish all five policies on one common state in every profile;
  - require four-way semantic equivalence across desired-state formats;
  - define exact final-tree and declarative-log semantics, safe links,
    malformed-input behavior, bounds, independent derivations, mutations,
    and observation limits;
  - keep implementation, hash publication, candidate execution, scoring,
    sealing, model selection, and claims disabled.
- Evidence: an independent read-only adversarial review mapped the reusable
  workspace/family/identity/coverage/canary/documentation contracts with six
  parallel readers, then ran five reviewers each walking C1–C6 under a distinct
  lens (criteria audit, semantic consistency, Bash feasibility, workspace
  compatibility, bounds/process), deduplicated the findings, and subjected
  every material finding to three independent refuters. Two load-bearing code
  facts were re-verified directly against the repository rather than trusted
  from the reviewers: `cmp` is absent from the 155-member
  `FROZEN_BASH_NATIVE_EXECUTABLES` while `sha256sum`, `cksum`, `cp`, `awk`, and
  `jq` are present (`src/cbds/evaluation_specs.py:112-139`), and the coverage
  admission gate requires every family's `allowed_tools` to be a subset of that
  frozen set (`src/cbds/executable_development_coverage.py:435-441`).
- Findings that survived verification:
  - **blocker** — the round-1 corrected tuple named `cmp`, which is not in the
    frozen bash-native allowlist; admitting it would fail the coverage subset
    gate or widen the sealed/scored tool policy;
  - **blocker** — the map-based safe-link conditions classified self-links and
    mutual link cycles as safe, contradicting the "cycles are not safe" prose
    and the mandatory cyclic-alias mutant;
  - **major** — the `empty-duplicates` profile could not both cover a wholly
    empty actual/desired tree and distinguish all five policies (C3 conflict);
  - **major** — final-tree semantics were undefined when an actual leaf is a
    proper ancestor of a desired leaf (witness: actual `a/b`, desired `a/b/c`);
  - plus one refuted candidate (mode-000 unreadable payloads) whose underlying
    clarification was still folded in, and five minor precision gaps
    (defer decision-string mapping, `LC_ALL=C`, `find -printf '%l'`,
    residue-free `mv`, and non-reuse of `validate_expected_output_policy`).
- Runtime, seeds, and cost: a read-only source/design review on the recorded
  CPython 3.14.4 / Linux 7.0.0-27-generic environment. The one randomized
  differential seam was not exercised; no training or model seed applies. The
  review used a background multi-agent workflow (27 agents, no shared artifact
  or hash published). All five reviewers independently returned `modify`.
- Claim boundary: design diagnosis only; no task behavior, candidate
  feasibility, 500-task review, score, or model result.
- Decision: `modify`.
- Rationale: two blockers made the round-1 contract unimplementable as written
  (a disallowed tool and a self-contradictory safe-link rule) and two majors
  left constructible inputs undefined; each is a design defect, not an
  implementation detail.
- Next authorized action: the corrected revision 2 of the design (recorded in
  the design doc's revision history) must receive its own independent review
  (`infra-016c`) before any family identity is implemented or frozen. This
  decision does not authorize implementation.

## Review: `infra-016c-symlink-revision2-rereview`

- Status: `complete`.
- Scope: revisions 2–4 of the corrected prospective contract in
  [SYMLINK_TREE_RECONCILE_DESIGN.md](SYMLINK_TREE_RECONCILE_DESIGN.md).
- Predecessor: the `infra-016b` `modify` decision (commit `3979b62`).
- Question: do the revision-2 corrections close the `infra-016b` findings
  without introducing new defects, leaving a design that is coherent enough to
  freeze family identities against?
- Acceptance criteria: the same preregistered C1–C6 as `infra-016b`, plus no
  new blocker or major introduced by the corrections.
- Evidence: two successive independent read-only passes. The first re-review
  (12 agents: five reviewers — closure, two regression lenses, criteria
  recheck, fresh defect hunt — then triage and three-refuter verification)
  confirmed the four substantive `infra-016b` corrections closed
  (`cmp → sha256sum` tuple subset, safe-link cycle exclusion, empty-profile
  discrimination, cross-tree ancestor invariant) but found two `major` textual
  regressions the revision-2 edits had themselves introduced (a verifier
  paragraph re-asserting leaf-less public bundles, and an empty-CSV encoding
  mislabelled zero-byte instead of header-only) plus three minors, each
  confirmed 3/3 at high confidence. Revision 3 fixed all five. A final
  verification pass (three reviewers — closure, whole-document empty/leaf-less
  consistency sweep, fresh adversarial skim — then three-refuter verification)
  returned **zero** blocker/major findings and votes of accept /
  accept-with-minor-edits / accept-with-minor-edits; revision 4 applied its two
  minor and one note wording tightenings.
- Runtime, seeds, and cost: read-only source/design reviews on the recorded
  CPython 3.14.4 / Linux 7.0.0-27-generic environment; no randomized,
  training, or model seed applies. Background multi-agent workflows only
  (12 + 3 agents); no shared artifact or hash was published. The one code-level
  cross-check re-ran the coverage suites (`tests.test_executable_development_coverage`
  and `_v8`, 35 tests) unchanged to confirm no regression, since only Markdown
  was edited.
- Claim boundary: design diagnosis only; no task behavior, candidate
  feasibility, 500-task review, score, or model result. The coverage-v8 planned
  7-tool record remains frozen and immutable; the tuple correction is exposed
  only by the future backward-linked coverage promotion, not by this review.
- Decision: `merge`.
- Rationale: every preregistered criterion passes, the two blockers and two
  majors from `infra-016b` are closed, and the final adversarial pass found no
  surviving blocker or major. The corrected contract fully specifies the
  codecs, five policies, safe-link semantics, final-tree and log semantics,
  bounds, independent derivations, mutation battery, and Bash-feasibility gate
  without widening the frozen instrument or enabling any authority.
- Next authorized action: implement the family-local types, codecs, semantic
  engines, fixtures, and custom verifier for `symlink-aware-tree-reconcile`
  **without publishing identities** (design publication sequence step 2), then
  run the mutation, equivalence, discrimination, resource, and Bash-canary
  gates as a distinct reviewed branch. Registry, catalog/report, coverage-v9
  promotion, sealing, scoring, model selection, and claims remain unauthorized
  until their own reviews.

## Review: `infra-016d-symlink-implementation`

- Status: `review in progress` (not a decision; no downstream work is
  permitted from this marker).
- Scope: the `symlink-aware-tree-reconcile` family implementation authorized by
  the `infra-016c` `merge`, built in reviewed increments without publishing any
  identity.
- Predecessor: the `infra-016c` `merge` decision (commit `59b01a5`).
- Increment 1 (this entry): the family-local *primary* semantic core in
  `src/cbds/executable_symlink_aware_tree_reconcile.py` — the immutable leaf
  model and exact-match equality, the four desired-state decoders (JSONL, CSV,
  NUL records, and an in-memory directory-blueprint decoder), the one-hop
  map-based six-condition safe-link alias rule, the union leaf/ancestor
  invariant, the five reconciliation policies with their final-tree and
  decision derivation, and the byte-exact `operations.tsv` serializer. Resource
  bounds are enforced. No task contract, normalized graph, `domain_sha256`
  commitment, registry, catalog, coverage promotion, oracle, workspace binding,
  or Bash canary is created by this increment.
- Increment-1 evidence: `tests.test_executable_symlink_aware_tree_reconcile`
  passes 27/27 in normal and optimized Python. It covers four-format decode,
  cross-format equivalence (a differential check across the four independent
  decoders), the full per-format malformed-rejection set, exact-duplicate
  collapse and conflict rejection, all five policies pairwise distinct on one
  common M/X/E/A/exact state, every safe-link corner case (positive, self-link,
  mutual cycle, chain, dangling, directory target, unequal content), the
  cross-tree ancestor rejection, byte-exact log serialization with an empty
  union, and representative bounds.
- Remaining increments before this branch can receive a decision: the
  independent reference engine with monkeypatch-enforced separation, the
  third test-only raw-fixture derivation, the workspace-integrated directory
  decoders and on-disk fixture construction, the custom bundle/oracle/verifier,
  the full mutation battery, the worst-case resource witnesses, the 20 task
  contracts and 100 fixture bundles, and the reviewed Bash feasibility canary.
- Claim boundary: public, unsealed, unscored, nonauthorizing static synthetic
  infrastructure. This increment establishes no identity and enables no
  authority.
