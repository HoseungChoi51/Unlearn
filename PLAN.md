# Target-Conditional Capacity Recycling for Static Bash Synthesis

## Summary and claim boundary

Develop and test **Target-Conditional Capacity Recycling (TCCR)**: identify structured FFN channels associated with an empirically interfering programming capability, retire them, reinitialize the same fixed parameter budget, and train those channels for executable Bash synthesis.

The primary model will be `SmolLM2-135M-Instruct`; the winning result will be repeated on `SmolLM2-135M` base. `SmolLM3-3B` will be a secondary offline teacher, not required by the main method.

The study will target **static Bash program synthesis**, not general interactive Linux use. “Unlearning” will mean measurable functional de-specialization, not certified deletion of training data. A strong “pretraining capacity competition” claim will require the controlled from-scratch experiment below.

## Literature verdict and novelty

Search cutoff: **2026-07-14**.

- The broad thesis is not novel. [Forget-to-Focus](https://openreview.net/forum?id=vGkXf8nvt9), an ICLR 2026 submission, already applies unlearning before domain fine-tuning and reports downstream gains. [Exclusive Unlearning](https://arxiv.org/abs/2604.06154) suppresses everything outside a retained domain.
- Structured specialization is also established. [Cus-Prun](https://aclanthology.org/2025.findings-acl.1201/) prunes target-irrelevant neurons; [Neuron Specialization](https://aclanthology.org/2024.emnlp-main.374/) uses language-specific FFN masks; [post-pruning recovery](https://arxiv.org/abs/2604.27115), [PAC-Net](https://proceedings.mlr.press/v162/myung22a.html), [FOMO](https://proceedings.iclr.cc/paper_files/paper/2024/hash/a439259e78294c38d157a51a2c40486b-Abstract-Conference.html), and recent [EPnG](https://arxiv.org/abs/2607.01789) cover prune/reset/regrow ideas in adjacent settings. “Capacity recycling” also appears in continual-unlearning work such as the unpublished [AmnesiacHAT draft](https://pengxiang-wang.com/unlisted/paper-draft-amnesiachat).
- Gradient- or Fisher-based forget/retain parameter selection is close prior art, including [Selective Synaptic Dampening](https://ojs.aaai.org/index.php/AAAI/article/view/29092), [selective LLM pruning](https://arxiv.org/abs/2403.01267), and [PerTA](https://arxiv.org/abs/2601.22030).
- Programming abilities are entangled. A controlled study across programming languages found cross-language effects after unlearning, including interactions among Shell, Python, and C++ knowledge; therefore no language may be declared irrelevant in advance. [Findings ACL 2024](https://aclanthology.org/2024.findings-acl.559/)
- Unlearning evaluations are fragile: TOFU found that its tested baselines did not reproduce retraining behavior; localized parameters need not be uniquely causal; apparently forgotten knowledge can often be recovered by benign fine-tuning. [TOFU](https://arxiv.org/abs/2401.06121), [localization study](https://aclanthology.org/2025.emnlp-main.1109/), [robust evaluation](https://arxiv.org/abs/2402.16835), [relearning attacks](https://openreview.net/forum?id=fMNRYBvcQN)
- Training-time removable modules are a strong alternative. The July 2026 [GRAM preprint](https://arxiv.org/abs/2607.08077) routes capabilities into removable modules during pretraining and approximates filtered-data retraining.

The defensible novelty is therefore:

> Post-hoc recycling of existing dense-LM SwiGLU channels, selected using both measured source–target interference and prospective Bash learnability, followed by execution-grounded training and channel-level causal mediation tests.

Do not claim the first use of forgetting for specialization, pruning followed by recovery, or capacity recycling generally.

## Experimental assets and feasibility gates

### Models and capabilities

The [SmolLM2-135M-Instruct model](https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct) has 30 layers, hidden width 576, FFN width 1,536, and was pretrained on 2T tokens. Its “15 programming languages” describe Stack-Edu data buckets, not demonstrated mastery.

Protect these prerequisites throughout:

- English instruction following and basic reasoning
- Bash, Unix concepts, regex and text processing
- Python
- Markdown, JSON, YAML and structured output
- Control flow, algorithms and numeracy

Audit these candidate capabilities without assuming they are harmful:

- C, C++, Java, JavaScript, TypeScript, C#, PHP
- SQL, Go, Rust, Ruby and Swift

A candidate is eligible only if the original model achieves at least 20% compile/syntax success and 5% functional pass@1 with at least 20 successes on 400 calibration tasks. Candidates at behavioral floor cannot support an “unlearning” claim.

### Sealed executable Bash suite

Create a generator-backed benchmark with:

- 12,000 training specifications
- 1,000 cross-fitted mask-selection specifications
- 500 method-development specifications
- 500 shadow-validation specifications
- 1,000 sealed in-distribution test specifications
- 500 sealed compositional-OOD specifications

Each specification is a distinct semantic operator/dependency graph, not a repeated textual template. Split by normalized program graph, utility composition, filesystem-state schema, and output contract. Report prompt, AST, command-graph, and execution-trace nearest-neighbor leakage.

Cover file operations, search, pipelines, regex/text transformation, permissions, processes, archives/checksums, JSON/CSV, quoting, error handling, functions and short control-flow scripts. The Bash-native primary track permits Bash built-ins plus a pinned allowlist of GNU utilities and `jq`; it disallows Python, Perl, compilers and network tools. A Python-permitted track is secondary.

For each scored specification, run the single generated program against at least five hidden fixtures, including spaces, leading dashes, globs, empty input, symlinks, duplicate records, permission failures and ordering variation. A task passes only if all fixtures satisfy property/state-based checks.

Execution must use a fresh rootless container with:

- Pinned Bash/coreutils/findutils/grep/sed/gawk/jq versions and image digest
- No network, host mounts, container socket or extra capabilities
- Read-only root, isolated writable workspace and `no-new-privileges`
- PID, CPU, memory, output and timeout limits
- Fixed locale, timezone, umask, UID/GID and shell options

Freeze the response parser before evaluation: accept raw Bash or one optional Markdown code fence, and separately report extraction failures, truncation, syntax failure, timeout and functional failure. Validate verifiers with mutation testing, an independent reference implementation and a stratified human audit of at least 100 tasks.

Use [NL2SH](https://arxiv.org/abs/2502.06858) training data alongside the generated training set, sampled 50/50 by source. Its 600-item test and NL2Bash are diagnostic because of possible pretraining exposure. Independently confirm on [BashBench](https://arxiv.org/abs/2606.27733); use 50 items to audit its harness and exclude those items from the scored subset.

Before sealing tests:

- Ordinary dense SFT must achieve 5–85% pass@1 on development data, preserving room above floor and below ceiling.
- At least one candidate capability must pass the competence and interference gates.
- Otherwise report a principled null or redesign task difficulty before any final evaluation.

## TCCR method

### Atomic recyclable unit

Use one SwiGLU intermediate channel:

- One row of `gate_proj`
- The matching row of `up_proj`
- The matching column of `down_proj`

SmolLM2 therefore has 46,080 candidate units. A 5% intervention recycles 2,304 channels, approximately 3.98M weights. Keep attention unchanged in the main study.

Implement recycling as a temporary side branch:

1. Mask the selected old channel activations to zero while retaining their archived weights.
2. Add the same number of fresh SwiGLU channels.
3. Initialize new gate/up rows with the checkpoint initializer and the new down matrix to zero. The initial model is therefore exactly the retired model rather than a randomly perturbed model.
4. Train only the new down matrix for 100 optimizer steps, then all three new matrices.
5. Merge the trained side branch into the selected positions for an unchanged 135M exported architecture.

This prevents optimizer state or weight decay from modifying supposedly frozen tensor slices and enables exact swap-back experiments.

### Skill and channel selection

For each eligible candidate skill \(F\), Bash target \(T\), and protected mixture \(R\):

1. Compute channel Taylor saliency \(A_s(u)=E|h_u\,\partial L_s/\partial h_u|\).
2. Compute per-channel gradient conflict
   \(C_F(u)=\max(0,-\cos(\nabla_uL_F,\nabla_uL_T))\).
3. Convert saliencies to within-layer percentiles and rank with
   \(S(u)=A_F(u)C_F(u)[1-\max(A_T(u),A_R(u))]\).
4. Require conflict direction and ranking to replicate across two calibration halves and three sampling seeds.
5. Treat short positive/negative task-vector probes only as eligibility evidence; they do not by themselves prove that pretrained skill capacity harms Bash.
6. Rank eligible skills and use at most the top three, equally weighted after per-skill percentile normalization. Evaluate nested one-skill, two-skill and three-skill forget sets on development data.

Add prospective Bash learnability:

- Within every layer, divide the top 20% static candidates into deterministic 32-channel blocks.
- For each block, retire it, initialize its replacement, perform 16 fixed Bash inner updates, and measure held-out Bash improvement relative to retirement-only.
- Rank blocks by prospective improvement while enforcing immediate forget-skill damage and protected-skill constraints.
- Construct layer-stratified masks at approximately 1%, 2.5%, 5% and 10%.
- Run the same 1M-token micro-adaptation for each dose and choose exactly one dose on method-development data.

A **target-only prospective selector** receives the same number of evaluated blocks and updates but no forget-skill signal. It is a mandatory control for determining whether TCCR gains come from selective forgetting or merely finding plastic Bash-friendly channels.

### Training

Use 20M optimizer-visible tokens per main arm, sampled 80% Bash and 20% protected replay. Apply cross-entropy on Bash and KL anchoring to the frozen original model on protected data.

- Side-only learning-rate grid: `{1e-4, 3e-4, 1e-3}`
- Full-model learning-rate grid: `{1e-5, 3e-5}`
- AdamW β=`(0.9, 0.95)`, gradient clipping 1.0, 5% warmup, cosine decay
- At most six development configurations per arm, with equal tuning budgets
- Checkpoint selection only on shadow validation

The confirmatory mechanism model keeps the nonselected backbone frozen throughout. A separate practical `TCCR-Joint` variant trains the side branch for the first 80% of tokens and jointly unfreezes the preserved backbone at low learning rate for the final 20%.

## Baselines and causal tests

### Required screening matrix

Run three paired seeds for:

- Original checkpoint and ordinary dense Bash SFT
- Dense SFT with extra steps matched to TCCR’s total measured selection/training FLOPs
- Forget-to-Focus gradient ascent plus retain descent, followed by identical Bash SFT
- Exclusive-Unlearning-style entropy suppression plus retain training
- Cus-Prun-style target-low-importance pruning and recovery
- Layer-matched random reset-and-regrow
- Target-low-saliency reset-and-regrow
- Target-only prospective recycle
- Forget-high/target-low static selection without prospective scoring
- A competent but nonnegative-transfer “wrong skill” recycle
- TCCR-selected channels trained from their original weights without reset
- TCCR retirement with no regrowth
- Full frozen-backbone TCCR and `TCCR-Joint`
- An equal-width added side branch that does not retire old channels, reported as a capacity-expansion ceiling

All structured controls use identical channel counts, per-layer quotas, data, steps and optimizer schedules.

Promote dense SFT, random recycle, target-only prospective recycle, TCCR, and the strongest established targeted baseline to eight fresh confirmation seeds. Repeat dense, random and TCCR with five seeds on SmolLM2-135M base.

Report both equal-target-token and equal-total-FLOP comparisons, including selection and look-ahead computation.

### Mechanism interventions

Evaluate immediately after retirement, after Bash regrowth and after the complete training schedule.

- **Swap-back:** remove learned replacement channels and restore the archived originals. The candidate skill should recover and TCCR’s incremental Bash gain should decline.
- **Re-zero:** disable learned replacement channels while keeping originals retired. The TCCR-specific Bash gain should decline.
- **Attribution:** measure Bash gradient energy and activation/ablation attribution moving into recycled channels.
- **Relearning:** apply a fixed 250k-token benign fine-tune for each forgotten skill and measure recovery using normal prompts, partial programs and prefix completions.
- **Selectivity:** compare the chosen capability’s degradation with matched nonselected programming languages.

If the preserved backbone is jointly unfrozen, mechanism conclusions must come from the separate frozen-backbone experiment.

## Evaluation and statistical acceptance

### Metrics

Primary target endpoint:

- Macro-averaged deterministic functional pass@1 across the 1,000 sealed semantic specifications

Secondary endpoints:

- Sealed compositional-OOD pass@1
- BashBench functionality and full-pass rates
- Syntax validity, ShellCheck diagnostics, AST similarity and output length
- NL2SH/NL2Bash diagnostic scores
- Single-line versus multi-line and difficulty-stratified results

Forgotten capabilities:

- Language-specific executable beginner/idiom tasks
- MultiPL-E where supported
- Compile/syntax rate and held-out code likelihood
- SQL execution rather than string matching
- Multiple prompt and prefix variants

Protected capabilities:

- FineWeb-Edu validation perplexity
- IFEval, PIQA and HellaSwag
- Python executable/compile tests
- Structured-format and Unix-concept probes

### Statistics

- Pair arms by training seed, data order, task and fixture.
- Bootstrap at the semantic-specification level, nesting fixtures within specifications and crossing training seed with task.
- Use paired randomization tests and Holm-adjusted 95% confidence intervals for primary contrasts.
- Freeze failure, timeout, rerun, exclusion, decoding and checkpoint policies before opening the sealed test.
- Run the sealed suite once after method and analysis lock.

TCCR succeeds only if all conditions hold:

1. `TCCR-Joint` exceeds dense SFT and frozen TCCR exceeds target-only prospective recycling, with adjusted lower confidence bounds above zero and point estimates of at least +3 absolute pass@1 points.
2. Frozen TCCR also exceeds random and static skill-only recycling in the predicted direction.
3. An above-floor selected capability falls by at least 3 absolute points and 20% relative, significantly more than matched nonselected languages.
4. FineWeb perplexity increases no more than 5%; English accuracy declines no more than 2 points; Python and structured/Unix probes decline no more than 3 points under simultaneous non-inferiority intervals.
5. Swap-back and re-zero effects have paired confidence intervals excluding zero in their predicted directions.
6. The result survives fresh seeds, equal-compute controls, the base checkpoint and at least one independent Bash benchmark.
7. The main effect exists without a teacher.

Interpret failures explicitly:

- Random recycle matches TCCR: generic plasticity or regularization.
- Target-only selection matches TCCR: prospective sparse specialization.
- No-reset sparse tuning matches TCCR: parameter-efficient specialization without forgetting.
- Target gain occurs without selective skill loss: targeted reinitialization.
- Skill loss occurs without swap mediation: correlated suppression, not demonstrated recycling.
- No capable, negatively transferring skill is found: a valuable null result against the initial premise.

## Teacher and controlled-pretraining studies

### Secondary teacher factorial

After freezing the teacher-free method, run a 2×2 comparison:

- Dense SFT versus TCCR
- Oracle-only data versus oracle plus SmolLM3-3B data

For each training prompt, have [SmolLM3-3B](https://huggingface.co/HuggingFaceTB/SmolLM3-3B) generate two `/no_think` candidates, expanding to four only when neither passes. Execute them and keep the shortest candidate that passes all training fixtures and has no serious ShellCheck error.

The teacher receives only training prompts—not sealed prompts, fixtures, reference programs, verifier code or benchmark failure reports. Use sequence distillation tokenized by the student tokenizer; do not use naïve logit distillation because teacher and student vocabularies differ. Both dense and TCCR arms receive the identical verified teacher corpus.

### Triggered 27M controlled study

If the 135M study meets target-superiority and mechanism criteria, run a preregistered from-scratch confirmation before claiming genuine pretraining-capacity competition.

Train a roughly 27M-parameter, 12-layer SwiGLU Llama-style model with hidden size 384, FFN size 1,024, six attention heads and a fixed 16k tokenizer. Use 600M tokens per run and three seeds.

Compare:

1. Full English/Bash/Python/candidate-language mixture
2. Candidate languages removed and replaced by length-matched retained English, keeping Bash/Python exposure and total tokens fixed
3. Candidate languages replaced by extra Bash data, reported separately as practical target-data reallocation
4. Full mixture with GRAM-style removable modules
5. Full mixture followed by TCCR

Use identical initializations, data ordering where applicable, compute and downstream Bash SFT. This determines whether filtered pretraining genuinely helps at fixed target exposure and whether post-hoc TCCR approaches the filtered-data model. Without this stage, limit the conclusion to behavior-guided post-hoc capacity reallocation.

## Reproducibility, compute and schedule

Store immutable manifests containing model revisions, data hashes, semantic-graph hashes, container digest, mask indices, archived and replacement channel weights, hyperparameters, seeds, measured FLOPs, teacher provenance and per-task outputs.

The RTX 5090 has [32GB VRAM](https://www.nvidia.com/en-us/geforce/graphics-cards/50-series/rtx-5090/). Full BF16 AdamW for 135M parameters should fit comfortably; a 5% side branch adds only about 4M trainable weights. SmolLM3-3B BF16 inference requires roughly 6GB for weights. Use BF16, packed 1–2k sequences, SDPA/FlashAttention, gradient checkpointing and an initial microbatch of 8 with accumulation adjusted after a two-hour throughput pilot.

Expected campaign:

- Days 1–3: generator, sandbox, verifier mutation tests, data splits and hashes
- Day 4: throughput, floor/ceiling and candidate-competence gates
- Days 5–6: signed-transfer audit, saliency/conflict collection and prospective mask search
- Days 7–10: three-seed screening matrix
- Days 11–14: eight-seed confirmation, causal swaps and base-model replication
- Days 15–16: secondary teacher factorial
- Additional 4–7 GPU-days: triggered controlled 27M pretraining study

Actual wall time will be recalibrated from measured training and sandbox-evaluation throughput. The student experiments should be memory-light; executable evaluation, mask search and the number of controlled arms will dominate runtime.
